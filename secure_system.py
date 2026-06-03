from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4
import ipaddress
import json
import logging
import os
import secrets
import shutil
import socket
import sqlite3
import urllib.request

from flask import Flask, abort, jsonify, redirect, render_template_string, request, send_file, session as browser_session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent


def get_storage_root():
    configured = os.environ.get("SECURE_STORAGE_DIR")
    if configured:
        return Path(configured)
    if os.environ.get("VERCEL"):
        return Path("/tmp") / "secure_storage"
    return BASE_DIR / "secure_storage"


SECURE_STORAGE = get_storage_root()
UPLOADS_DIR = SECURE_STORAGE / "uploads"
BACKUPS_DIR = SECURE_STORAGE / "backups"
EXPORTS_DIR = SECURE_STORAGE / "exports"
LOGS_DIR = SECURE_STORAGE / "logs"
DB_PATH = SECURE_STORAGE / "secure_system.db"

for directory in (SECURE_STORAGE, UPLOADS_DIR, BACKUPS_DIR, EXPORTS_DIR, LOGS_DIR):
    directory.mkdir(parents=True, exist_ok=True)


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECURE_APP_SECRET", secrets.token_hex(32)),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    JSON_SORT_KEYS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

logging.basicConfig(
    filename=str(LOGS_DIR / "secure_app.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "json", "csv", "md"}
SESSION_DURATION = timedelta(hours=8)
ROLE_LEVELS = {
    "user": 10,
    "analyst": 20,
    "admin": 80,
}

users = {}
sessions = {}
documents = {}
folders = {}
audit_events = []


def get_db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_db_connection()
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS app_state (
            state_key TEXT PRIMARY KEY,
            state_value TEXT NOT NULL
        )
        """
    )
    connection.commit()
    connection.close()


def persist_state(keys=None):
    key_list = keys or ["users", "documents", "folders", "audit_events"]
    state_map = {
        "users": users,
        "documents": documents,
        "folders": folders,
        "audit_events": audit_events,
    }

    connection = get_db_connection()
    for state_key in key_list:
        connection.execute(
            """
            INSERT INTO app_state(state_key, state_value)
            VALUES(?, ?)
            ON CONFLICT(state_key) DO UPDATE SET state_value = excluded.state_value
            """,
            (state_key, json.dumps(state_map[state_key], ensure_ascii=False)),
        )
    connection.commit()
    connection.close()


def load_state():
    global users, documents, folders, audit_events

    connection = get_db_connection()
    rows = connection.execute("SELECT state_key, state_value FROM app_state").fetchall()
    connection.close()

    state_map = {row["state_key"]: json.loads(row["state_value"]) for row in rows}
    users = state_map.get("users", {})
    documents = state_map.get("documents", {})
    folders = state_map.get("folders", {})
    audit_events = state_map.get("audit_events", [])


def build_sqlite_preview(value):
    if isinstance(value, dict):
        return {
            "kind": "dict",
            "items": len(value),
            "preview": list(value.keys())[:5],
        }
    if isinstance(value, list):
        preview = []
        for item in value[:3]:
            if isinstance(item, dict):
                preview.append({
                    key: item[key]
                    for key in ("actor", "action", "timestamp", "username", "id", "name")
                    if key in item
                })
            else:
                preview.append(item)
        return {
            "kind": "list",
            "items": len(value),
            "preview": preview,
        }
    return {
        "kind": type(value).__name__,
        "items": 1,
        "preview": value,
    }


def get_sqlite_summary():
    db_exists = DB_PATH.exists()
    db_size = DB_PATH.stat().st_size if db_exists else 0
    modified_at = datetime.fromtimestamp(DB_PATH.stat().st_mtime, timezone.utc).astimezone().strftime("%d/%m/%Y %H:%M") if db_exists else "-"

    connection = get_db_connection()
    rows = connection.execute(
        "SELECT state_key, state_value, LENGTH(state_value) AS payload_size FROM app_state ORDER BY state_key"
    ).fetchall()
    connection.close()

    state_rows = []
    for row in rows:
        value = json.loads(row["state_value"])
        state_rows.append({
            "state_key": row["state_key"],
            "payload_size": row["payload_size"],
            "summary": build_sqlite_preview(value),
        })

    return {
        "path": str(DB_PATH),
        "exists": db_exists,
        "size_bytes": db_size,
        "size_human": format_file_size(db_size),
        "modified_at": modified_at,
        "state_rows": state_rows,
    }


def utc_now():
    return datetime.now(timezone.utc)


def iso_now():
    return utc_now().isoformat()


def wants_html_response():
    accept = request.headers.get("Accept", "")
    return "text/html" in accept and not request.path.startswith("/api/")


def is_form_post():
    content_type = request.content_type or ""
    return request.method == "POST" and "application/json" not in content_type


def set_notice(kind, text):
    browser_session["notice"] = {"kind": kind, "text": text}


def pop_notice():
    return browser_session.pop("notice", None)


def create_folder(owner, name, parent_id=None):
    folder_id = str(uuid4())
    folder = {
        "id": folder_id,
        "name": name,
        "owner": owner,
        "parent_id": parent_id,
        "created_at": iso_now(),
    }
    folders[folder_id] = folder
    user_dir = UPLOADS_DIR / owner / folder_id
    user_dir.mkdir(parents=True, exist_ok=True)
    persist_state(["folders"])
    return folder


def create_user(username, password, email, role="user"):
    users[username] = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "role": role,
        "email": email,
        "created_at": iso_now(),
        "root_folder_id": None,
    }
    root_folder = create_folder(username, "Documentos", None)
    users[username]["root_folder_id"] = root_folder["id"]
    persist_state(["users", "folders"])
    return users[username]


def serialize_user(user):
    return {
        "username": user["username"],
        "role": user["role"],
        "email": user["email"],
        "created_at": user["created_at"],
        "root_folder_id": user["root_folder_id"],
    }


def serialize_folder(folder):
    return {
        "id": folder["id"],
        "name": folder["name"],
        "owner": folder["owner"],
        "parent_id": folder["parent_id"],
        "created_at": folder["created_at"],
    }


def serialize_document(document):
    return {
        "id": document["id"],
        "original_name": document["original_name"],
        "stored_name": document["stored_name"],
        "owner": document["owner"],
        "folder_id": document["folder_id"],
        "content_type": document["content_type"],
        "size": document["size"],
        "created_at": document["created_at"],
        "shared_with": document["shared_with"],
    }


def audit(actor, action, status="success", metadata=None):
    entry = {
        "timestamp": iso_now(),
        "actor": actor,
        "action": action,
        "status": status,
        "metadata": metadata or {},
        "ip": request.remote_addr,
    }
    audit_events.append(entry)
    logging.info(json.dumps(entry, ensure_ascii=True))
    persist_state(["audit_events"])
    return entry


def cleanup_expired_sessions():
    now = utc_now()
    expired_tokens = [
        token for token, session_data in sessions.items()
        if session_data["expires_at"] <= now
    ]
    for token in expired_tokens:
        sessions.pop(token, None)


def extract_token():
    cleanup_expired_sessions()
    header = request.headers.get("Authorization", "").strip()
    if header:
        if header.lower().startswith("bearer "):
            return header.split(" ", 1)[1].strip()
        return header
    return browser_session.get("session_token")


def issue_session(username):
    token = secrets.token_urlsafe(32)
    expires_at = utc_now() + SESSION_DURATION
    sessions[token] = {
        "username": username,
        "expires_at": expires_at,
        "created_at": utc_now(),
    }
    browser_session["session_token"] = token
    return token, expires_at


def start_pending_login(username):
    browser_session["pending_2fa_user"] = username


def get_pending_login_username():
    return browser_session.get("pending_2fa_user")


def clear_pending_login():
    browser_session.pop("pending_2fa_user", None)


def destroy_session(token=None):
    active_token = token or extract_token()
    if active_token:
        sessions.pop(active_token, None)
    browser_session.pop("session_token", None)
    clear_pending_login()


def get_current_username():
    token = extract_token()
    if not token:
        return None
    session_data = sessions.get(token)
    if not session_data:
        browser_session.pop("session_token", None)
        return None
    return session_data["username"]


def get_current_user():
    username = get_current_username()
    if not username:
        return None
    return users.get(username)


def get_role_level(role):
    return ROLE_LEVELS.get(role, 0)


def has_role(user, minimum_role):
    if not user:
        return False
    return get_role_level(user["role"]) >= get_role_level(minimum_role)


def can_manage_user(actor, target):
    if not actor or not target:
        return False
    if actor["username"] == target["username"]:
        return False
    return get_role_level(actor["role"]) > get_role_level(target["role"])


def username_has_documents(username):
    return any(document["owner"] == username for document in documents.values())


def username_has_active_session(username):
    return any(session_data["username"] == username for session_data in sessions.values())


def revoke_sessions_for(username):
    tokens = [token for token, session_data in sessions.items() if session_data["username"] == username]
    for token in tokens:
        sessions.pop(token, None)


def auth_required(view_function):
    @wraps(view_function)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            if wants_html_response():
                set_notice("error", "Debes iniciar sesion para continuar.")
                return redirect(url_for("login"))
            return jsonify({"error": "Autenticacion requerida"}), 401
        return view_function(*args, **kwargs)

    return wrapper


def admin_required(view_function):
    @wraps(view_function)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            if wants_html_response():
                set_notice("error", "Debes iniciar sesion como administrador.")
                return redirect(url_for("login"))
            return jsonify({"error": "Autenticacion requerida"}), 401
        if not has_role(user, "admin"):
            if wants_html_response():
                set_notice("error", "Tu cuenta no tiene permisos de administrador.")
                return redirect(url_for("dashboard"))
            return jsonify({"error": "Permisos insuficientes"}), 403
        return view_function(*args, **kwargs)

    return wrapper


def require_json():
    if not request.is_json:
        abort(400, description="Se esperaba un cuerpo JSON")
    return request.get_json() or {}


def validate_username(username):
    if not username or len(username) < 3 or len(username) > 30:
        return False
    return username.replace("_", "").replace("-", "").isalnum()


def validate_password(password):
    if not password or len(password) < 8:
        return False
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    return has_upper and has_lower and has_digit


def validate_email(email):
    return bool(email) and "@" in email and "." in email.split("@", 1)[-1]


def allowed_extension(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def folder_for_user(folder_id, username):
    folder = folders.get(folder_id)
    if not folder:
        return None
    if folder["owner"] != username and users[username]["role"] != "admin":
        return None
    return folder


def document_path(owner, folder_id, stored_name):
    return (UPLOADS_DIR / owner / folder_id / stored_name).resolve()


def is_safe_document_path(path, owner, folder_id):
    expected_base = (UPLOADS_DIR / owner / folder_id).resolve()
    try:
        path.relative_to(expected_base)
        return True
    except ValueError:
        return False


def can_access_document(username, document, write_required=False):
    if not username:
        return False
    user = users.get(username)
    if not user:
        return False
    if user["role"] == "admin":
        return True
    if document["owner"] == username:
        return True
    permission = document["shared_with"].get(username)
    if write_required:
        return permission == "write"
    return permission in {"read", "write"}


def get_document_or_404(document_id):
    document = documents.get(document_id)
    if not document:
        abort(404, description="Documento no encontrado")
    return document


def is_public_url(target_url):
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False

    try:
        resolved = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    except socket.gaierror:
        return False

    for _, _, _, _, sockaddr in resolved:
        ip_text = sockaddr[0]
        ip_obj = ipaddress.ip_address(ip_text)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False

    return True


def format_file_size(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def visible_documents_for(username, query="", extension="", owner=""):
    query = (query or "").strip().lower()
    extension = (extension or "").strip().lower().lstrip(".")
    owner = (owner or "").strip()

    result = []
    for document in documents.values():
        if not can_access_document(username, document):
            continue
        if owner and not has_role(users[username], "admin") and owner != username:
            continue
        if owner and document["owner"] != owner:
            continue
        if query and query not in document["original_name"].lower():
            continue
        if extension and not document["original_name"].lower().endswith(f".{extension}"):
            continue
        result.append(document)
    return sorted(result, key=lambda item: item["created_at"], reverse=True)


def folders_for_user(username):
    return sorted(
        [folder for folder in folders.values() if folder["owner"] == username],
        key=lambda item: item["created_at"],
    )


def recent_history_for(username, limit=12):
    current_user = users[username]
    relevant = []
    for event in audit_events:
        if has_role(current_user, "admin") or event["actor"] == username:
            relevant.append(event)
    return list(reversed(relevant[-limit:]))


def build_dashboard_context(username, search_query="", search_ext="", search_owner=""):
    user = users[username]
    documents_list = visible_documents_for(username, search_query, search_ext, search_owner)
    own_documents = [document for document in documents.values() if document["owner"] == username]
    shared_documents = [
        document for document in documents_list
        if document["owner"] != username
    ]
    folders_list = folders_for_user(username)
    session_data = sessions.get(extract_token())

    admin_data = None
    if has_role(user, "admin"):
        admin_data = {
            "users": [serialize_user(entry) for entry in users.values()],
            "active_sessions": len(sessions),
            "events": list(reversed(audit_events[-10:])),
            "sqlite": get_sqlite_summary(),
            "roles": sorted(ROLE_LEVELS.keys(), key=lambda role: ROLE_LEVELS[role]),
            "manageable_users": {
                entry["username"]: can_manage_user(user, entry)
                for entry in users.values()
            },
        }

    return {
        "current_user": serialize_user(user),
        "documents": [serialize_document(document) for document in documents_list],
        "folders": [serialize_folder(folder) for folder in folders_list],
        "history": recent_history_for(username),
        "share_targets": sorted([name for name in users if name != username]),
        "stats": {
            "all_visible": len(documents_list),
            "owned": len(own_documents),
            "shared": len(shared_documents),
            "folders": len(folders_list),
        },
        "session_expires": session_data["expires_at"].strftime("%d/%m/%Y %H:%M") if session_data else "-",
        "search": {
            "q": search_query,
            "ext": search_ext,
            "owner": search_owner,
        },
        "admin_data": admin_data,
        "allowed_extensions": ", ".join(sorted(ALLOWED_EXTENSIONS)),
        "format_file_size": format_file_size,
        "notice": pop_notice(),
        "can_admin": has_role(user, "admin"),
    }


def initialize_data():
    if users:
        return
    create_user("admin", "Admin1234", "admin@secure.local", role="admin")
    create_user("analista", "Analista123", "analista@secure.local", role="analyst")


init_db()
load_state()
initialize_data()


LANDING_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Secure Document Hub</title>
    <style>
        :root {
            --bg: #efe8dc;
            --ink: #17202a;
            --muted: #5f6974;
            --accent: #0b5d66;
            --accent-strong: #08363b;
            --panel: rgba(255, 250, 243, 0.9);
            --line: rgba(23, 32, 42, 0.12);
            --shadow: 0 30px 80px rgba(23, 32, 42, 0.15);
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            color: var(--ink);
            font-family: Cambria, Cochin, Georgia, Times, "Times New Roman", serif;
            background:
                radial-gradient(circle at top left, rgba(11, 93, 102, 0.18), transparent 32%),
                radial-gradient(circle at 80% 20%, rgba(201, 125, 20, 0.18), transparent 24%),
                linear-gradient(145deg, #f3ede3, #ebdfcf 48%, #e5d8c5 100%);
        }

        .shell {
            max-width: 1200px;
            margin: 0 auto;
            padding: 28px 22px 70px;
        }

        .nav {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 18px;
            margin-bottom: 30px;
        }

        .brand {
            font-size: 1.05rem;
            letter-spacing: 0.18em;
            text-transform: uppercase;
            color: var(--accent);
            font-weight: 700;
        }

        .nav-actions {
            display: flex;
            gap: 12px;
        }

        .button, .button-secondary {
            text-decoration: none;
            border-radius: 999px;
            padding: 12px 18px;
            font-weight: 700;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .button {
            color: white;
            background: linear-gradient(135deg, var(--accent), var(--accent-strong));
            box-shadow: 0 16px 30px rgba(11, 93, 102, 0.22);
        }

        .button-secondary {
            color: var(--ink);
            background: rgba(255, 255, 255, 0.7);
            border: 1px solid var(--line);
        }

        .hero {
            display: grid;
            grid-template-columns: 1.3fr 0.9fr;
            gap: 22px;
            align-items: stretch;
        }

        .hero-card, .feature-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 30px;
            box-shadow: var(--shadow);
            backdrop-filter: blur(12px);
        }

        .hero-card {
            padding: 36px;
        }

        .eyebrow {
            color: var(--accent);
            text-transform: uppercase;
            letter-spacing: 0.18em;
            font-size: 0.78rem;
            margin: 0 0 14px;
            font-weight: 700;
        }

        h1 {
            margin: 0;
            line-height: 0.95;
            font-size: clamp(2.8rem, 6vw, 5.4rem);
            max-width: 700px;
        }

        .summary {
            max-width: 760px;
            color: var(--muted);
            font-size: 1.08rem;
            line-height: 1.7;
            margin-top: 20px;
        }

        .hero-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 14px;
            margin-top: 28px;
        }

        .stat {
            padding: 18px;
            border-radius: 22px;
            background: rgba(255, 255, 255, 0.78);
            border: 1px solid var(--line);
        }

        .stat strong {
            display: block;
            font-size: 2.1rem;
        }

        .panel-list {
            padding: 28px;
            display: grid;
            gap: 14px;
        }

        .feature-card {
            padding: 22px;
        }

        .feature-card h3 {
            margin: 0 0 12px;
            font-size: 1.2rem;
        }

        .feature-card p, .panel-list li {
            color: var(--muted);
            line-height: 1.65;
        }

        .features {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 18px;
            margin-top: 22px;
        }

        @media (max-width: 920px) {
            .hero, .features {
                grid-template-columns: 1fr;
            }

            .hero-grid {
                grid-template-columns: 1fr 1fr;
            }
        }

        @media (max-width: 640px) {
            .nav {
                flex-direction: column;
                align-items: flex-start;
            }

            .nav-actions, .hero-grid {
                width: 100%;
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="shell">
        <div class="nav">
            <div class="brand">Secure Document Hub</div>
            <div class="nav-actions">
                <a class="button-secondary" href="{{ url_for('register') }}">Crear cuenta</a>
                <a class="button" href="{{ url_for('login') }}">Iniciar sesion</a>
            </div>
        </div>

        <section class="hero">
            <article class="hero-card">
                <p class="eyebrow">Sistema documental seguro</p>
                <h1>Gestion profesional de archivos y sesiones seguras</h1>
                <p class="summary">
                    Plataforma web completa para registro de usuarios, autenticacion, permisos por recurso,
                    carga y descarga de archivos, carpetas, auditoria, panel administrativo y busqueda avanzada.
                    Esta version esta preparada para operar correctamente desde navegador y desde API REST.
                </p>
                <div class="hero-grid">
                    <div class="stat">
                        <strong>{{ users_count }}</strong>
                        Usuarios disponibles
                    </div>
                    <div class="stat">
                        <strong>{{ docs_count }}</strong>
                        Documentos activos
                    </div>
                    <div class="stat">
                        <strong>{{ folders_count }}</strong>
                        Carpetas gestionadas
                    </div>
                    <div class="stat">
                        <strong>{{ events_count }}</strong>
                        Eventos auditados
                    </div>
                </div>
            </article>
            <aside class="hero-card panel-list">
                <div>
                    <h3>Operativo desde la web</h3>
                    <p>Login visual, dashboard con formularios, subida de archivos, comparticion y panel de control.</p>
                </div>
                <div>
                    <h3>Seguridad aplicada</h3>
                    <p>Hash de passwords, tokens aleatorios, permisos por recurso y mitigacion de SSRF y Path Traversal.</p>
                </div>
                <div>
                    <h3>API y panel admin</h3>
                    <p>Los mismos datos se exponen de forma controlada por endpoints REST y vistas web protegidas.</p>
                </div>
            </aside>
        </section>

        <section class="features">
            <article class="feature-card">
                <h3>Flujos del usuario</h3>
                <p>Registro, login, sesiones, carga, descarga, eliminacion y manejo de carpetas desde el navegador.</p>
            </article>
            <article class="feature-card">
                <h3>Colaboracion</h3>
                <p>Comparticion de documentos y gestion detallada de permisos de lectura y escritura.</p>
            </article>
            <article class="feature-card">
                <h3>Visibilidad</h3>
                <p>Busqueda avanzada, historial de actividad, auditoria y reportes para perfiles administradores.</p>
            </article>
        </section>
    </div>
</body>
</html>
"""


AUTH_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }}</title>
    <style>
        :root {
            --bg: #10151c;
            --bg-2: #18212c;
            --surface: rgba(248, 244, 238, 0.92);
            --ink: #16212a;
            --muted: #60707d;
            --accent: #0f766e;
            --accent-strong: #11424b;
            --warn: #9f1239;
            --line: rgba(22, 33, 42, 0.14);
            --shadow: 0 28px 70px rgba(0, 0, 0, 0.28);
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: Cambria, Cochin, Georgia, Times, "Times New Roman", serif;
            color: var(--ink);
            background:
                radial-gradient(circle at 18% 20%, rgba(15, 118, 110, 0.28), transparent 22%),
                radial-gradient(circle at 80% 12%, rgba(245, 158, 11, 0.18), transparent 22%),
                linear-gradient(145deg, var(--bg), var(--bg-2) 60%, #0b1118 100%);
            display: grid;
            place-items: center;
            padding: 24px;
        }

        .layout {
            width: min(1100px, 100%);
            display: grid;
            grid-template-columns: 1.1fr 0.9fr;
            border-radius: 34px;
            overflow: hidden;
            box-shadow: var(--shadow);
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }

        .showcase {
            padding: 44px;
            color: white;
            background:
                linear-gradient(180deg, rgba(11, 17, 24, 0.1), rgba(11, 17, 24, 0.46)),
                linear-gradient(145deg, #0c4550, #0b1118 75%);
        }

        .showcase h1 {
            margin: 18px 0 16px;
            font-size: clamp(2.6rem, 5vw, 4.8rem);
            line-height: 0.95;
        }

        .showcase p {
            max-width: 520px;
            color: rgba(255, 255, 255, 0.8);
            line-height: 1.7;
        }

        .tag {
            display: inline-flex;
            padding: 8px 12px;
            border-radius: 999px;
            background: rgba(255, 255, 255, 0.12);
            letter-spacing: 0.16em;
            text-transform: uppercase;
            font-size: 0.76rem;
        }

        .showcase ul {
            margin-top: 24px;
            padding-left: 18px;
            color: rgba(255, 255, 255, 0.82);
            line-height: 1.9;
        }

        .panel {
            background: var(--surface);
            padding: 42px;
        }

        .topline {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            align-items: center;
        }

        .topline a {
            color: var(--accent);
            text-decoration: none;
            font-weight: 700;
        }

        h2 {
            font-size: 2rem;
            margin-bottom: 10px;
        }

        .muted {
            color: var(--muted);
            line-height: 1.7;
        }

        .notice {
            margin-top: 18px;
            padding: 14px 16px;
            border-radius: 16px;
            border: 1px solid transparent;
        }

        .notice.error {
            background: rgba(159, 18, 57, 0.08);
            color: var(--warn);
            border-color: rgba(159, 18, 57, 0.14);
        }

        .notice.success {
            background: rgba(15, 118, 110, 0.08);
            color: var(--accent-strong);
            border-color: rgba(15, 118, 110, 0.14);
        }

        form {
            display: grid;
            gap: 16px;
            margin-top: 26px;
        }

        label {
            font-size: 0.92rem;
            font-weight: 700;
            display: grid;
            gap: 8px;
        }

        input {
            width: 100%;
            padding: 14px 16px;
            border-radius: 16px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, 0.8);
            font-size: 1rem;
        }

        .submit {
            margin-top: 6px;
            border: 0;
            cursor: pointer;
            color: white;
            border-radius: 18px;
            padding: 14px 20px;
            font-size: 1rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent), var(--accent-strong));
            box-shadow: 0 18px 30px rgba(15, 118, 110, 0.22);
        }

        .subtle {
            margin-top: 20px;
            color: var(--muted);
            line-height: 1.7;
        }

        .subtle a {
            color: var(--accent);
            font-weight: 700;
            text-decoration: none;
        }

        @media (max-width: 920px) {
            .layout {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="layout">
        <section class="showcase">
            <span class="tag">Secure access</span>
            <h1>{{ hero_title }}</h1>
            <p>{{ hero_text }}</p>
            <ul>
                <li>Autenticacion segura con sesiones protegidas</li>
                <li>Dashboard web con operaciones reales</li>
                <li>Permisos por archivo, carpeta y rol</li>
                <li>Auditoria, busqueda y panel administrativo</li>
            </ul>
        </section>
        <section class="panel">
            <div class="topline">
                <strong>Secure Document Hub</strong>
                <a href="{{ url_for('home') }}">Volver al inicio</a>
            </div>
            <h2>{{ heading }}</h2>
            <p class="muted">{{ description }}</p>
            {% if notice %}
            <div class="notice {{ notice.kind }}">{{ notice.text }}</div>
            {% endif %}
            <form method="post" action="{{ action }}">
                {% if mode == 'register' %}
                <label>Correo
                    <input name="email" type="email" placeholder="nombre@empresa.cl" required>
                </label>
                {% endif %}
                {% if two_factor_stage %}
                <label>Codigo de verificacion
                    <input name="two_factor_code" type="password" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" placeholder="123123" required>
                </label>
                <p class="muted">Usuario en validacion: <strong>{{ pending_username }}</strong>. Para esta demo, el codigo seguro es 123123.</p>
                {% else %}
                <label>Usuario
                    <input name="username" type="text" placeholder="usuario" required>
                </label>
                <label>Clave
                    <input name="password" type="password" placeholder="********" required>
                </label>
                {% endif %}
                {% if mode == 'register' %}
                <p class="muted">La clave debe incluir al menos 8 caracteres, una mayuscula, una minuscula y un numero.</p>
                {% endif %}
                <button class="submit" type="submit">{{ button_text }}</button>
            </form>
            <p class="subtle">
                {% if mode == 'login' %}
                Si aun no tienes cuenta, <a href="{{ url_for('register') }}">registrate aqui</a>.
                {% else %}
                Si ya tienes acceso, <a href="{{ url_for('login') }}">ingresa con tu cuenta</a>.
                {% endif %}
            </p>
        </section>
    </div>
</body>
</html>
"""


DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Panel | Secure Document Hub</title>
    <style>
        :root {
            --ink: #17202a;
            --muted: #5b6772;
            --accent: #0c6c74;
            --accent-dark: #0c3e45;
            --panel: rgba(255, 252, 246, 0.92);
            --line: rgba(23, 32, 42, 0.1);
            --shadow: 0 24px 64px rgba(23, 32, 42, 0.12);
            --danger: #be123c;
            --success: #0f766e;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            color: var(--ink);
            font-family: Cambria, Cochin, Georgia, Times, "Times New Roman", serif;
            background:
                radial-gradient(circle at top left, rgba(12, 108, 116, 0.18), transparent 28%),
                radial-gradient(circle at bottom right, rgba(200, 125, 23, 0.14), transparent 24%),
                linear-gradient(145deg, #f6f0e5, #ece2d2 52%, #e3d8c8 100%);
        }

        .layout {
            display: grid;
            grid-template-columns: 290px 1fr;
            gap: 22px;
            max-width: 1440px;
            margin: 0 auto;
            padding: 24px;
        }

        .sidebar, .panel, .hero, .table-card, .form-card, .mini-card {
            background: var(--panel);
            border: 1px solid var(--line);
            box-shadow: var(--shadow);
            backdrop-filter: blur(10px);
        }

        .sidebar {
            border-radius: 30px;
            padding: 24px;
            position: sticky;
            top: 24px;
            height: fit-content;
        }

        .brand {
            margin-bottom: 24px;
        }

        .brand small {
            display: block;
            color: var(--accent);
            letter-spacing: 0.16em;
            text-transform: uppercase;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .brand h1 {
            margin: 0;
            font-size: 2.4rem;
            line-height: 0.95;
        }

        .profile {
            padding: 18px;
            border-radius: 22px;
            background: rgba(255, 255, 255, 0.74);
            border: 1px solid var(--line);
        }

        .profile strong, .mini-card strong {
            display: block;
            font-size: 1.2rem;
        }

        .profile p, .side-note, .table-card td, .table-card th {
            color: var(--muted);
        }

        .menu {
            margin: 24px 0;
            display: grid;
            gap: 10px;
        }

        .menu a {
            text-decoration: none;
            padding: 12px 14px;
            border-radius: 16px;
            color: var(--ink);
            font-weight: 700;
            background: rgba(255, 255, 255, 0.56);
            border: 1px solid var(--line);
        }

        .logout button, .action-primary, .action-secondary, .action-danger {
            border: 0;
            cursor: pointer;
            border-radius: 16px;
            font-weight: 700;
            padding: 12px 16px;
        }

        .logout button, .action-primary {
            background: linear-gradient(135deg, var(--accent), var(--accent-dark));
            color: white;
        }

        .action-secondary {
            background: rgba(255, 255, 255, 0.85);
            border: 1px solid var(--line);
            color: var(--ink);
        }

        .action-danger {
            background: rgba(190, 18, 60, 0.12);
            color: var(--danger);
        }

        .content {
            display: grid;
            gap: 22px;
        }

        .hero {
            border-radius: 32px;
            padding: 28px;
        }

        .hero-top {
            display: flex;
            justify-content: space-between;
            gap: 18px;
            align-items: flex-start;
            flex-wrap: wrap;
        }

        .hero-top h2 {
            margin: 10px 0 12px;
            font-size: clamp(2rem, 4vw, 3.4rem);
            line-height: 0.95;
        }

        .hero-top p {
            color: var(--muted);
            max-width: 760px;
            line-height: 1.7;
        }

        .notice {
            margin-top: 18px;
            padding: 14px 16px;
            border-radius: 16px;
        }

        .notice.success {
            background: rgba(15, 118, 110, 0.09);
            color: var(--success);
        }

        .notice.error {
            background: rgba(190, 18, 60, 0.08);
            color: var(--danger);
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 14px;
            margin-top: 22px;
        }

        .mini-card {
            border-radius: 22px;
            padding: 18px;
            background: rgba(255, 255, 255, 0.74);
        }

        .mini-card span {
            display: block;
            color: var(--muted);
            margin-top: 6px;
        }

        .grid-2 {
            display: grid;
            grid-template-columns: 1.1fr 0.9fr;
            gap: 22px;
        }

        .grid-3 {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 18px;
        }

        .table-card, .form-card, .panel {
            border-radius: 28px;
            padding: 22px;
        }

        .table-card h3, .form-card h3 {
            margin: 0 0 12px;
            font-size: 1.3rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            text-align: left;
            padding: 12px 8px;
            border-bottom: 1px solid var(--line);
            vertical-align: top;
        }

        .tag {
            display: inline-flex;
            padding: 6px 10px;
            border-radius: 999px;
            background: rgba(12, 108, 116, 0.1);
            color: var(--accent-dark);
            font-size: 0.85rem;
            font-weight: 700;
        }

        .tag.admin {
            background: rgba(200, 125, 23, 0.14);
            color: #8a4b00;
        }

        .meta {
            font-size: 0.92rem;
            color: var(--muted);
        }

        .inline-form, .stack-form {
            display: grid;
            gap: 12px;
        }

        .inline-form {
            grid-template-columns: repeat(4, 1fr);
            align-items: end;
        }

        label {
            display: grid;
            gap: 8px;
            font-size: 0.92rem;
            font-weight: 700;
        }

        input, select {
            width: 100%;
            padding: 13px 14px;
            border-radius: 14px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, 0.82);
            color: var(--ink);
        }

        .actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .table-actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .history-list {
            display: grid;
            gap: 12px;
        }

        .history-item {
            border-radius: 18px;
            padding: 14px 16px;
            background: rgba(255, 255, 255, 0.74);
            border: 1px solid var(--line);
        }

        .history-item strong {
            display: block;
            margin-bottom: 4px;
        }

        .empty {
            color: var(--muted);
            line-height: 1.7;
            padding: 10px 0;
        }

        @media (max-width: 1200px) {
            .layout {
                grid-template-columns: 1fr;
            }

            .sidebar {
                position: static;
            }

            .grid-2, .grid-3, .stats, .inline-form {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="brand">
                <small>Panel seguro</small>
                <h1>Document Hub</h1>
            </div>
            <div class="profile">
                <strong>{{ current_user.username }}</strong>
                <p>{{ current_user.email }}</p>
                <span class="tag {% if can_admin %}admin{% endif %}">{{ current_user.role }}</span>
                <p class="side-note">Sesion activa hasta {{ session_expires }}</p>
            </div>
            <nav class="menu">
                <a href="#documents">Documentos</a>
                <a href="#operations">Operaciones</a>
                <a href="#history">Historial</a>
                <a href="#audit">Auditoria</a>
                {% if admin_data %}<a href="#admin">Panel admin</a>{% endif %}
                {% if admin_data %}<a href="#sqlite">SQLite</a>{% endif %}
                {% if admin_data %}<a href="#user-management">Usuarios</a>{% endif %}
            </nav>
            <form class="logout" method="post" action="{{ url_for('logout') }}">
                <button type="submit">Cerrar sesion</button>
            </form>
        </aside>

        <main class="content">
            <section class="hero">
                <div class="hero-top">
                    <div>
                        <span class="tag">Aplicacion operativa</span>
                        <h2>Gestiona archivos, permisos y auditoria desde una sola vista</h2>
                        <p>
                            El sistema ahora opera correctamente desde navegador: registro, login, sesiones,
                            subida y descarga de archivos, compartir documentos, carpetas, API REST, historial,
                            panel administrativo, busqueda avanzada y gestion de permisos.
                        </p>
                    </div>
                    <div class="actions">
                        <form method="post" action="{{ url_for('backup') }}">
                            <button class="action-secondary" type="submit">Generar backup</button>
                        </form>
                        {% if admin_data %}
                        <a class="action-primary" href="{{ url_for('export_metadata') }}" style="text-decoration:none;display:inline-flex;align-items:center;">Exportar metadata</a>
                        {% endif %}
                    </div>
                </div>
                {% if notice %}
                <div class="notice {{ notice.kind }}">{{ notice.text }}</div>
                {% endif %}
                <div class="stats">
                    <article class="mini-card"><strong>{{ stats.all_visible }}</strong><span>Documentos visibles</span></article>
                    <article class="mini-card"><strong>{{ stats.owned }}</strong><span>Documentos propios</span></article>
                    <article class="mini-card"><strong>{{ stats.shared }}</strong><span>Compartidos contigo</span></article>
                    <article class="mini-card"><strong>{{ stats.folders }}</strong><span>Carpetas gestionadas</span></article>
                </div>
            </section>

            <section class="form-card" id="operations">
                <h3>Busqueda avanzada</h3>
                <form class="inline-form" method="get" action="{{ url_for('dashboard') }}">
                    <label>Nombre o palabra clave
                        <input name="q" value="{{ search.q }}" placeholder="Contrato, informe, nota...">
                    </label>
                    <label>Extension
                        <input name="ext" value="{{ search.ext }}" placeholder="pdf, txt, csv">
                    </label>
                    <label>Propietario
                        <input name="owner" value="{{ search.owner }}" placeholder="Solo admin para terceros">
                    </label>
                    <button class="action-primary" type="submit">Buscar</button>
                </form>
            </section>

            <section class="grid-3">
                <article class="form-card">
                    <h3>Subir archivo</h3>
                    <form class="stack-form" method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data">
                        <label>Carpeta
                            <select name="folder_id">
                                {% for folder in folders %}
                                <option value="{{ folder.id }}">{{ folder.name }}</option>
                                {% endfor %}
                            </select>
                        </label>
                        <label>Archivo
                            <input type="file" name="file" required>
                        </label>
                        <span class="meta">Extensiones permitidas: {{ allowed_extensions }}</span>
                        <button class="action-primary" type="submit">Guardar archivo</button>
                    </form>
                </article>
                <article class="form-card">
                    <h3>Crear carpeta</h3>
                    <form class="stack-form" method="post" action="{{ url_for('manage_folders') }}">
                        <label>Nombre de carpeta
                            <input type="text" name="name" placeholder="Ejemplo: Proyectos 2026" required>
                        </label>
                        <label>Carpeta padre
                            <select name="parent_id">
                                {% for folder in folders %}
                                <option value="{{ folder.id }}">{{ folder.name }}</option>
                                {% endfor %}
                            </select>
                        </label>
                        <button class="action-primary" type="submit">Crear carpeta</button>
                    </form>
                </article>
                <article class="form-card" id="audit">
                    <h3>Auditoria URL</h3>
                    <form class="stack-form" method="post" action="{{ url_for('audit_url_check') }}">
                        <label>URL publica
                            <input type="url" name="url" placeholder="https://example.com" required>
                        </label>
                        <button class="action-primary" type="submit">Validar URL</button>
                    </form>
                </article>
            </section>

            <section class="grid-2">
                <article class="table-card" id="documents">
                    <h3>Documentos</h3>
                    {% if documents %}
                    <table>
                        <thead>
                            <tr>
                                <th>Archivo</th>
                                <th>Propietario</th>
                                <th>Permisos</th>
                                <th>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for document in documents %}
                            <tr>
                                <td>
                                    <strong>{{ document.original_name }}</strong>
                                    <div class="meta">{{ format_file_size(document.size) }} | {{ document.content_type }} | {{ document.created_at[:10] }}</div>
                                </td>
                                <td>{{ document.owner }}</td>
                                <td>
                                    {% if document.shared_with %}
                                        {% for target, permission in document.shared_with.items() %}
                                        <div class="meta">{{ target }}: {{ permission }}</div>
                                        {% endfor %}
                                    {% else %}
                                        <span class="meta">Privado</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <div class="table-actions">
                                        <a class="action-secondary" href="{{ url_for('download', document_id=document.id) }}" style="text-decoration:none;display:inline-flex;align-items:center;">Descargar</a>
                                        {% if can_admin or document.owner == current_user.username %}
                                        <form method="post" action="{{ url_for('share_document') }}">
                                            <input type="hidden" name="document_id" value="{{ document.id }}">
                                            <select name="target" required>
                                                <option value="">Compartir con</option>
                                                {% for target in share_targets %}
                                                <option value="{{ target }}">{{ target }}</option>
                                                {% endfor %}
                                            </select>
                                            <select name="permission">
                                                <option value="read">read</option>
                                                <option value="write">write</option>
                                            </select>
                                            <button class="action-secondary" type="submit">Compartir</button>
                                        </form>
                                        <form method="post" action="{{ url_for('delete_document_web', document_id=document.id) }}">
                                            <button class="action-danger" type="submit">Eliminar</button>
                                        </form>
                                        {% endif %}
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <p class="empty">No hay documentos para mostrar con los filtros actuales.</p>
                    {% endif %}
                </article>

                <article class="table-card">
                    <h3>Carpetas</h3>
                    {% if folders %}
                    <table>
                        <thead>
                            <tr>
                                <th>Nombre</th>
                                <th>Creada</th>
                                <th>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for folder in folders %}
                            <tr>
                                <td>
                                    <strong>{{ folder.name }}</strong>
                                    <div class="meta">ID {{ folder.id[:8] }}</div>
                                </td>
                                <td>{{ folder.created_at[:10] }}</td>
                                <td>
                                    {% if folder.id != current_user.root_folder_id or can_admin %}
                                    <form method="post" action="{{ url_for('delete_folder_web', folder_id=folder.id) }}">
                                        <button class="action-danger" type="submit">Eliminar</button>
                                    </form>
                                    {% else %}
                                    <span class="meta">Carpeta raiz protegida</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <p class="empty">No existen carpetas registradas.</p>
                    {% endif %}
                </article>
            </section>

            <section class="grid-2">
                <article class="table-card" id="history">
                    <h3>Historial de actividad</h3>
                    {% if history %}
                    <div class="history-list">
                        {% for item in history %}
                        <div class="history-item">
                            <strong>{{ item.action }} | {{ item.status }}</strong>
                            <div class="meta">{{ item.timestamp }} | {{ item.actor }} | IP {{ item.ip }}</div>
                            <div class="meta">{{ item.metadata }}</div>
                        </div>
                        {% endfor %}
                    </div>
                    {% else %}
                    <p class="empty">Todavia no hay actividad registrada.</p>
                    {% endif %}
                </article>

                <article class="table-card">
                    <h3>API REST disponible</h3>
                    <div class="history-list">
                        <div class="history-item"><strong>POST /register</strong><div class="meta">Registro de usuarios por JSON o formulario web.</div></div>
                        <div class="history-item"><strong>POST /login</strong><div class="meta">Autenticacion con token para API y cookie para navegador.</div></div>
                        <div class="history-item"><strong>GET /api/files</strong><div class="meta">Lista documentos visibles para el usuario autenticado.</div></div>
                        <div class="history-item"><strong>GET /api/folders</strong><div class="meta">Expone carpetas disponibles segun permisos.</div></div>
                        <div class="history-item"><strong>GET /admin</strong><div class="meta">Panel admin visual en navegador o JSON si se consume como API.</div></div>
                    </div>
                </article>
            </section>

            {% if admin_data %}
            <section class="panel" id="admin">
                <h3>Panel administrativo</h3>
                <div class="grid-3">
                    <article class="mini-card"><strong>{{ admin_data.users|length }}</strong><span>Usuarios totales</span></article>
                    <article class="mini-card"><strong>{{ admin_data.active_sessions }}</strong><span>Sesiones activas</span></article>
                    <article class="mini-card"><strong>{{ admin_data.events|length }}</strong><span>Eventos recientes</span></article>
                </div>
                <div class="grid-2" style="margin-top:18px;">
                    <article class="table-card">
                        <h3>Usuarios</h3>
                        <table>
                            <thead>
                                <tr><th>Usuario</th><th>Rol</th><th>Correo</th></tr>
                            </thead>
                            <tbody>
                                {% for user in admin_data.users %}
                                <tr>
                                    <td>{{ user.username }}</td>
                                    <td>{{ user.role }}</td>
                                    <td>{{ user.email }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </article>
                    <article class="table-card">
                        <h3>Ultimos eventos</h3>
                        <div class="history-list">
                            {% for item in admin_data.events %}
                            <div class="history-item">
                                <strong>{{ item.action }}</strong>
                                <div class="meta">{{ item.actor }} | {{ item.timestamp }}</div>
                                <div class="meta">{{ item.metadata }}</div>
                            </div>
                            {% endfor %}
                        </div>
                    </article>
                </div>
            </section>

            <section class="panel" id="sqlite">
                <h3>Estado SQLite</h3>
                <div class="grid-3">
                    <article class="mini-card"><strong>{{ admin_data.sqlite.size_human }}</strong><span>Tamano de la base local</span></article>
                    <article class="mini-card"><strong>{{ admin_data.sqlite.state_rows|length }}</strong><span>Bloques persistidos</span></article>
                    <article class="mini-card"><strong>{{ admin_data.sqlite.modified_at }}</strong><span>Ultima actualizacion</span></article>
                </div>
                <div class="grid-2" style="margin-top:18px;">
                    <article class="table-card">
                        <h3>Base de datos</h3>
                        <div class="history-list">
                            <div class="history-item">
                                <strong>Archivo SQLite</strong>
                                <div class="meta">{{ admin_data.sqlite.path }}</div>
                            </div>
                            <div class="history-item">
                                <strong>Estado</strong>
                                <div class="meta">{% if admin_data.sqlite.exists %}Disponible y operativa{% else %}No encontrada{% endif %}</div>
                            </div>
                        </div>
                    </article>
                    <article class="table-card">
                        <h3>Contenido persistido</h3>
                        <table>
                            <thead>
                                <tr><th>Clave</th><th>Items</th><th>Payload</th><th>Preview</th></tr>
                            </thead>
                            <tbody>
                                {% for row in admin_data.sqlite.state_rows %}
                                <tr>
                                    <td>{{ row.state_key }}</td>
                                    <td>{{ row.summary["items"] }}</td>
                                    <td>{{ format_file_size(row.payload_size) }}</td>
                                    <td class="meta">{{ row.summary.preview }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </article>
                </div>
            </section>

            <section class="panel" id="user-management">
                <h3>Gestion de usuarios</h3>
                <div class="grid-2" style="margin-top:18px;">
                    <article class="table-card">
                        <h3>Crear usuario</h3>
                        <form class="stack-form" method="post" action="{{ url_for('admin_create_user') }}">
                            <label>Usuario
                                <input type="text" name="username" placeholder="nuevo_usuario" required>
                            </label>
                            <label>Correo
                                <input type="email" name="email" placeholder="nuevo@secure.local" required>
                            </label>
                            <label>Clave temporal
                                <input type="password" name="password" placeholder="ClaveSegura123" required>
                            </label>
                            <label>Rol
                                <select name="role">
                                    {% for role_name in admin_data.roles %}
                                    <option value="{{ role_name }}">{{ role_name }}</option>
                                    {% endfor %}
                                </select>
                            </label>
                            <button class="action-primary" type="submit">Crear usuario</button>
                        </form>
                    </article>
                    <article class="table-card">
                        <h3>Cambiar mi clave</h3>
                        <form class="stack-form" method="post" action="{{ url_for('change_password') }}">
                            <label>Clave actual
                                <input type="password" name="current_password" required>
                            </label>
                            <label>Nueva clave
                                <input type="password" name="new_password" placeholder="NuevaClave123" required>
                            </label>
                            <button class="action-primary" type="submit">Actualizar clave</button>
                        </form>
                    </article>
                </div>
                <article class="table-card" style="margin-top:18px;">
                    <h3>Administrar cuentas</h3>
                    <table>
                        <thead>
                            <tr><th>Usuario</th><th>Rol</th><th>Correo</th><th>Acciones</th></tr>
                        </thead>
                        <tbody>
                            {% for managed_user in admin_data.users %}
                            <tr>
                                <td>{{ managed_user.username }}</td>
                                <td>{{ managed_user.role }}</td>
                                <td>{{ managed_user.email }}</td>
                                <td>
                                    <div class="table-actions">
                                        {% if managed_user.username == current_user.username %}
                                        <span class="meta">Cuenta actual</span>
                                        {% elif admin_data.manageable_users.get(managed_user.username) %}
                                        <form method="post" action="{{ url_for('admin_reset_password', username=managed_user.username) }}">
                                            <input type="password" name="new_password" placeholder="NuevaClave123" required>
                                            <button class="action-secondary" type="submit">Cambiar clave</button>
                                        </form>
                                        <form method="post" action="{{ url_for('admin_delete_user', username=managed_user.username) }}">
                                            <button class="action-danger" type="submit">Eliminar</button>
                                        </form>
                                        {% else %}
                                        <span class="meta">Sin permisos suficientes</span>
                                        {% endif %}
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </article>
            </section>
            {% endif %}
        </main>
    </div>
</body>
</html>
"""


def render_auth_page(mode):
    notice = pop_notice()
    pending_username = get_pending_login_username()
    two_factor_stage = mode == "login" and bool(pending_username)
    context = {
        "mode": mode,
        "notice": notice,
        "two_factor_stage": two_factor_stage,
        "pending_username": pending_username,
    }
    if mode == "login":
        context.update({
            "title": "Segundo factor | Secure Document Hub" if two_factor_stage else "Login | Secure Document Hub",
            "heading": "Verificar segundo factor" if two_factor_stage else "Iniciar sesion",
            "description": "Ingresa el codigo seguro de 6 digitos para completar el acceso." if two_factor_stage else "Accede a tu espacio documental con un panel profesional y controles de seguridad activos.",
            "button_text": "Validar acceso" if two_factor_stage else "Entrar al panel",
            "hero_title": "Segundo factor para un acceso seguro" if two_factor_stage else "Ingreso seguro para equipos y administradores",
            "hero_text": "Para esta simulacion usa el codigo 123123 y completa el acceso al panel." if two_factor_stage else "La aplicacion incluye autenticacion robusta, sesion de navegador protegida y operaciones completas desde la interfaz web.",
            "action": url_for("login"),
        })
    else:
        context.update({
            "title": "Registro | Secure Document Hub",
            "heading": "Crear cuenta",
            "description": "Registra un usuario nuevo con validaciones de correo, nombre y fortaleza de clave.",
            "button_text": "Crear cuenta segura",
            "hero_title": "Onboarding simple, serio y funcional",
            "hero_text": "Crea una cuenta y entra directamente a un panel con carpetas, archivos, historial y herramientas de colaboracion.",
            "action": url_for("register"),
        })
    return render_template_string(AUTH_TEMPLATE, **context)


def complete_registration(username, password, email):
    username = (username or "").strip()
    password = password or ""
    email = (email or "").strip().lower()

    if not validate_username(username):
        return None, "Nombre de usuario invalido", 400
    if username in users:
        return None, "El usuario ya existe", 409
    if not validate_password(password):
        return None, "La clave debe tener al menos 8 caracteres, mayuscula, minuscula y numero", 400
    if not validate_email(email):
        return None, "Correo invalido", 400

    user = create_user(username, password, email, role="user")
    audit(username, "register", metadata={"email": email})
    return user, None, 201


def authenticate_credentials(username, password):
    username = (username or "").strip()
    password = password or ""
    user = users.get(username)
    if not user or not check_password_hash(user["password_hash"], password):
        audit(username or "anonymous", "login", status="failed")
        return None, "Credenciales invalidas", 401
    return user, None, 200


def complete_login(username, password):
    user, error_message, status_code = authenticate_credentials(username, password)
    if error_message:
        return None, None, error_message, status_code

    token, expires_at = issue_session(user["username"])
    audit(user["username"], "login")
    return user, {"token": token, "expires_at": expires_at.isoformat()}, None, 200


def create_user_by_admin(actor, username, password, email, role):
    if not has_role(actor, "admin"):
        return None, "Permisos insuficientes", 403
    if role not in ROLE_LEVELS:
        return None, "Rol invalido", 400
    if not has_role(actor, role):
        return None, "No puedes crear usuarios con un rol superior al tuyo", 403
    return complete_registration(username, password, email) if role == "user" else _create_non_default_role(username, password, email, role)


def _create_non_default_role(username, password, email, role):
    username = (username or "").strip()
    password = password or ""
    email = (email or "").strip().lower()

    if not validate_username(username):
        return None, "Nombre de usuario invalido", 400
    if username in users:
        return None, "El usuario ya existe", 409
    if not validate_password(password):
        return None, "La clave debe tener al menos 8 caracteres, mayuscula, minuscula y numero", 400
    if not validate_email(email):
        return None, "Correo invalido", 400

    user = create_user(username, password, email, role=role)
    return user, None, 201


def update_password_for_user(target_user, new_password):
    if not validate_password(new_password):
        return "La nueva clave no cumple la politica de seguridad", 400
    target_user["password_hash"] = generate_password_hash(new_password)
    revoke_sessions_for(target_user["username"])
    persist_state(["users"])
    return None, 200


def upload_document_for_user(username, file_storage, folder_id):
    folder = folder_for_user(folder_id, username)
    if not folder:
        return None, "Carpeta no disponible", 404
    if not file_storage or not file_storage.filename:
        return None, "Debe adjuntar un archivo valido", 400

    safe_name = secure_filename(file_storage.filename)
    if not safe_name:
        return None, "Nombre de archivo invalido", 400
    if not allowed_extension(safe_name):
        return None, "Extension no permitida", 400

    document_id = str(uuid4())
    stored_name = f"{document_id}_{safe_name}"
    destination = document_path(username, folder_id, stored_name)
    if not is_safe_document_path(destination, username, folder_id):
        return None, "Ruta de almacenamiento invalida", 400

    destination.parent.mkdir(parents=True, exist_ok=True)
    file_storage.save(destination)
    document = {
        "id": document_id,
        "original_name": safe_name,
        "stored_name": stored_name,
        "owner": username,
        "folder_id": folder_id,
        "path": str(destination),
        "content_type": file_storage.mimetype or "application/octet-stream",
        "size": destination.stat().st_size,
        "created_at": iso_now(),
        "shared_with": {},
    }
    documents[document_id] = document
    persist_state(["documents"])
    audit(username, "upload", metadata={"document_id": document_id, "filename": safe_name})
    return document, None, 201


@app.errorhandler(400)
def bad_request(error):
    if wants_html_response():
        set_notice("error", str(error.description if hasattr(error, "description") else error))
        destination = "dashboard" if get_current_user() else "home"
        return redirect(url_for(destination))
    return jsonify({"error": str(error.description if hasattr(error, "description") else error)}), 400


@app.errorhandler(404)
def not_found(error):
    if wants_html_response():
        set_notice("error", str(error.description if hasattr(error, "description") else error))
        destination = "dashboard" if get_current_user() else "home"
        return redirect(url_for(destination))
    return jsonify({"error": str(error.description if hasattr(error, "description") else error)}), 404


@app.route("/")
def home():
    if get_current_user():
        return redirect(url_for("dashboard"))
    return render_template_string(
        LANDING_TEMPLATE,
        users_count=len(users),
        docs_count=len(documents),
        folders_count=len(folders),
        events_count=len(audit_events),
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_auth_page("register")

    if request.is_json:
        data = require_json()
        user, error_message, status_code = complete_registration(
            data.get("username"),
            data.get("password"),
            data.get("email"),
        )
        if error_message:
            return jsonify({"error": error_message}), status_code
        return jsonify({"message": "Usuario registrado", "user": serialize_user(user)}), status_code

    user, error_message, status_code = complete_registration(
        request.form.get("username"),
        request.form.get("password"),
        request.form.get("email"),
    )
    if error_message:
        set_notice("error", error_message)
        return redirect(url_for("register"))

    issue_session(user["username"])
    audit(user["username"], "login")
    set_notice("success", "Cuenta creada correctamente. Bienvenido al panel.")
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_auth_page("login")

    if request.is_json:
        data = require_json()
        user, session_payload, error_message, status_code = complete_login(
            data.get("username"),
            data.get("password"),
        )
        if error_message:
            return jsonify({"error": error_message}), status_code
        return jsonify({
            "token": session_payload["token"],
            "expires_at": session_payload["expires_at"],
            "user": serialize_user(user),
        })

    pending_username = get_pending_login_username()
    if pending_username:
        two_factor_code = (request.form.get("two_factor_code") or "").strip()
        if two_factor_code != "123123":
            set_notice("error", "Codigo de segundo factor invalido.")
            return redirect(url_for("login"))

        issue_session(pending_username)
        clear_pending_login()
        audit(pending_username, "login")
        set_notice("success", "Acceso correctamente. Segundo factor validado.")
        return redirect(url_for("dashboard"))

    user, error_message, _ = authenticate_credentials(
        request.form.get("username"),
        request.form.get("password"),
    )
    if error_message:
        clear_pending_login()
        set_notice("error", error_message)
        return redirect(url_for("login"))

    start_pending_login(user["username"])
    set_notice("success", "Credenciales correctas. Ingresa el codigo 123123 para completar el acceso.")
    return redirect(url_for("login"))


@app.route("/logout", methods=["POST"])
@auth_required
def logout():
    username = get_current_username()
    destroy_session()
    audit(username, "logout")
    if wants_html_response() or is_form_post():
        set_notice("success", "Sesion cerrada.")
        return redirect(url_for("login"))
    return jsonify({"message": "Sesion cerrada"})


@app.route("/account/password", methods=["POST"])
@auth_required
def change_password():
    user = get_current_user()
    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""

    if not check_password_hash(user["password_hash"], current_password):
        set_notice("error", "La clave actual no es correcta.")
        return redirect(url_for("dashboard") + "#user-management")

    error_message, _ = update_password_for_user(user, new_password)
    if error_message:
        set_notice("error", error_message)
        return redirect(url_for("dashboard") + "#user-management")

    audit(user["username"], "change_password", metadata={"target": user["username"]})
    token, _ = issue_session(user["username"])
    browser_session["session_token"] = token
    set_notice("success", "Clave actualizada correctamente.")
    return redirect(url_for("dashboard") + "#user-management")


@app.route("/admin/users", methods=["POST"])
@admin_required
def admin_create_user():
    actor = get_current_user()
    user, error_message, status_code = create_user_by_admin(
        actor,
        request.form.get("username"),
        request.form.get("password"),
        request.form.get("email"),
        request.form.get("role") or "user",
    )
    if error_message:
        set_notice("error", error_message)
        return redirect(url_for("dashboard") + "#user-management")

    audit(actor["username"], "admin_create_user", metadata={"target": user["username"], "role": user["role"]})
    set_notice("success", f"Usuario {user['username']} creado correctamente.")
    return redirect(url_for("dashboard") + "#user-management")


@app.route("/admin/users/<username>/password", methods=["POST"])
@admin_required
def admin_reset_password(username):
    actor = get_current_user()
    target_user = users.get(username)
    if not target_user:
        set_notice("error", "Usuario no encontrado.")
        return redirect(url_for("dashboard") + "#user-management")
    if not can_manage_user(actor, target_user):
        set_notice("error", "No tienes permisos para cambiar la clave de este usuario.")
        return redirect(url_for("dashboard") + "#user-management")

    error_message, _ = update_password_for_user(target_user, request.form.get("new_password") or "")
    if error_message:
        set_notice("error", error_message)
        return redirect(url_for("dashboard") + "#user-management")

    audit(actor["username"], "admin_change_password", metadata={"target": username})
    set_notice("success", f"Clave actualizada para {username}.")
    return redirect(url_for("dashboard") + "#user-management")


@app.route("/admin/users/<username>/delete", methods=["POST"])
@admin_required
def admin_delete_user(username):
    actor = get_current_user()
    target_user = users.get(username)
    if not target_user:
        set_notice("error", "Usuario no encontrado.")
        return redirect(url_for("dashboard") + "#user-management")
    if not can_manage_user(actor, target_user):
        set_notice("error", "No tienes permisos para eliminar este usuario.")
        return redirect(url_for("dashboard") + "#user-management")
    if username_has_documents(username):
        set_notice("error", "No se puede eliminar el usuario porque tiene documentos asociados.")
        return redirect(url_for("dashboard") + "#user-management")

    revoke_sessions_for(username)
    root_folder_id = target_user["root_folder_id"]
    for folder_id in [folder["id"] for folder in list(folders.values()) if folder["owner"] == username]:
        folders.pop(folder_id, None)
    shutil.rmtree(UPLOADS_DIR / username, ignore_errors=True)
    users.pop(username, None)
    persist_state(["users", "folders"])
    audit(actor["username"], "admin_delete_user", metadata={"target": username, "root_folder_id": root_folder_id})
    set_notice("success", f"Usuario {username} eliminado correctamente.")
    return redirect(url_for("dashboard") + "#user-management")


@app.route("/dashboard", methods=["GET"])
@auth_required
def dashboard():
    username = get_current_username()
    context = build_dashboard_context(
        username,
        request.args.get("q", ""),
        request.args.get("ext", ""),
        request.args.get("owner", ""),
    )
    return render_template_string(DASHBOARD_TEMPLATE, **context)


@app.route("/session", methods=["GET"])
@auth_required
def session_info():
    username = get_current_username()
    token = extract_token()
    session_data = sessions[token]
    return jsonify({
        "user": serialize_user(users[username]),
        "expires_at": session_data["expires_at"].isoformat(),
    })


@app.route("/upload", methods=["POST"])
@auth_required
def upload():
    username = get_current_username()
    folder_id = request.form.get("folder_id") or users[username]["root_folder_id"]
    document, error_message, status_code = upload_document_for_user(
        username,
        request.files.get("file"),
        folder_id,
    )
    if error_message:
        if wants_html_response() or is_form_post():
            set_notice("error", error_message)
            return redirect(url_for("dashboard"))
        return jsonify({"error": error_message}), status_code

    if wants_html_response() or is_form_post():
        set_notice("success", "Archivo cargado correctamente.")
        return redirect(url_for("dashboard"))
    return jsonify({"message": "Archivo cargado", "document": serialize_document(document)}), status_code


@app.route("/files", methods=["GET"])
@auth_required
def list_files():
    username = get_current_username()
    return jsonify([
        serialize_document(document)
        for document in visible_documents_for(username)
    ])


@app.route("/download/<document_id>", methods=["GET"])
@auth_required
def download(document_id):
    username = get_current_username()
    document = get_document_or_404(document_id)
    if not can_access_document(username, document):
        return jsonify({"error": "No tiene permisos para descargar este archivo"}), 403

    path = Path(document["path"]).resolve()
    if not is_safe_document_path(path, document["owner"], document["folder_id"]):
        return jsonify({"error": "Documento con ruta invalida"}), 400
    if not path.exists():
        return jsonify({"error": "Archivo no disponible"}), 404

    audit(username, "download", metadata={"document_id": document_id})
    return send_file(path, as_attachment=True, download_name=document["original_name"])


@app.route("/share", methods=["POST"])
@auth_required
def share_document():
    username = get_current_username()
    if request.is_json:
        data = require_json()
    else:
        data = request.form

    document_id = data.get("document_id")
    target = (data.get("target") or "").strip()
    permission = (data.get("permission") or "read").strip().lower()
    document = get_document_or_404(document_id)

    if permission not in {"read", "write"}:
        if wants_html_response() or is_form_post():
            set_notice("error", "Permiso invalido.")
            return redirect(url_for("dashboard"))
        return jsonify({"error": "Permiso invalido"}), 400
    if target not in users:
        if wants_html_response() or is_form_post():
            set_notice("error", "Usuario destino inexistente.")
            return redirect(url_for("dashboard"))
        return jsonify({"error": "Usuario destino inexistente"}), 404
    if document["owner"] != username and users[username]["role"] != "admin":
        if wants_html_response() or is_form_post():
            set_notice("error", "Solo el propietario o admin puede compartir.")
            return redirect(url_for("dashboard"))
        return jsonify({"error": "Solo el propietario o admin puede compartir"}), 403

    document["shared_with"][target] = permission
    persist_state(["documents"])
    audit(username, "share", metadata={"document_id": document_id, "target": target, "permission": permission})
    if wants_html_response() or is_form_post():
        set_notice("success", f"Documento compartido con {target}.")
        return redirect(url_for("dashboard"))
    return jsonify({"message": "Documento compartido", "document": serialize_document(document)})


@app.route("/permissions/<document_id>", methods=["GET", "POST"])
@auth_required
def manage_permissions(document_id):
    username = get_current_username()
    document = get_document_or_404(document_id)
    if document["owner"] != username and users[username]["role"] != "admin":
        return jsonify({"error": "Solo el propietario o admin puede ver o cambiar permisos"}), 403

    if request.method == "GET":
        return jsonify({
            "document_id": document_id,
            "shared_with": document["shared_with"],
        })

    data = require_json()
    target = (data.get("target") or "").strip()
    permission = (data.get("permission") or "read").strip().lower()
    if target not in users:
        return jsonify({"error": "Usuario destino inexistente"}), 404
    if permission not in {"read", "write", "remove"}:
        return jsonify({"error": "Permiso invalido"}), 400

    if permission == "remove":
        document["shared_with"].pop(target, None)
    else:
        document["shared_with"][target] = permission

    persist_state(["documents"])
    audit(username, "permissions_update", metadata={"document_id": document_id, "target": target, "permission": permission})
    return jsonify({"message": "Permisos actualizados", "document": serialize_document(document)})


@app.route("/files/<document_id>", methods=["DELETE"])
@auth_required
def delete_document(document_id):
    username = get_current_username()
    document = get_document_or_404(document_id)
    if document["owner"] != username and users[username]["role"] != "admin":
        return jsonify({"error": "Solo el propietario o admin puede eliminar"}), 403

    path = Path(document["path"]).resolve()
    if path.exists():
        path.unlink()
    documents.pop(document_id, None)
    persist_state(["documents"])
    audit(username, "delete_document", metadata={"document_id": document_id})
    return jsonify({"message": "Archivo eliminado"})


@app.route("/web/files/<document_id>/delete", methods=["POST"])
@auth_required
def delete_document_web(document_id):
    username = get_current_username()
    document = get_document_or_404(document_id)
    if document["owner"] != username and users[username]["role"] != "admin":
        set_notice("error", "No tienes permisos para eliminar este archivo.")
        return redirect(url_for("dashboard"))

    path = Path(document["path"]).resolve()
    if path.exists():
        path.unlink()
    documents.pop(document_id, None)
    persist_state(["documents"])
    audit(username, "delete_document", metadata={"document_id": document_id})
    set_notice("success", "Archivo eliminado correctamente.")
    return redirect(url_for("dashboard"))


@app.route("/folders", methods=["GET", "POST", "DELETE"])
@auth_required
def manage_folders():
    username = get_current_username()
    current_user = users[username]

    if request.method == "GET":
        requested_user = request.args.get("user", username)
        if requested_user != username and current_user["role"] != "admin":
            return jsonify({"error": "No puede consultar carpetas de otro usuario"}), 403
        return jsonify([
            serialize_folder(folder)
            for folder in folders.values()
            if folder["owner"] == requested_user
        ])

    if request.method == "POST":
        if request.is_json:
            data = require_json()
            name = (data.get("name") or "").strip()
            parent_id = data.get("parent_id") or users[username]["root_folder_id"]
        else:
            name = (request.form.get("name") or "").strip()
            parent_id = request.form.get("parent_id") or users[username]["root_folder_id"]

        if not name or len(name) > 80:
            if wants_html_response() or is_form_post():
                set_notice("error", "Nombre de carpeta invalido.")
                return redirect(url_for("dashboard"))
            return jsonify({"error": "Nombre de carpeta invalido"}), 400

        parent = folder_for_user(parent_id, username)
        if not parent:
            if wants_html_response() or is_form_post():
                set_notice("error", "Carpeta padre no disponible.")
                return redirect(url_for("dashboard"))
            return jsonify({"error": "Carpeta padre no disponible"}), 404

        folder = create_folder(username, secure_filename(name) or name, parent_id=parent_id)
        audit(username, "create_folder", metadata={"folder_id": folder["id"]})
        if wants_html_response() or is_form_post():
            set_notice("success", "Carpeta creada correctamente.")
            return redirect(url_for("dashboard"))
        return jsonify({"message": "Carpeta creada", "folder": serialize_folder(folder)}), 201

    folder_id = request.args.get("folder_id")
    folder = folder_for_user(folder_id, username)
    if not folder:
        return jsonify({"error": "Carpeta no disponible"}), 404
    if folder_id == users[username]["root_folder_id"] and current_user["role"] != "admin":
        return jsonify({"error": "No puede eliminar la carpeta raiz"}), 400

    has_documents = any(document["folder_id"] == folder_id for document in documents.values())
    has_children = any(child["parent_id"] == folder_id for child in folders.values())
    if has_documents or has_children:
        return jsonify({"error": "La carpeta no esta vacia"}), 400

    folder_path = UPLOADS_DIR / folder["owner"] / folder_id
    shutil.rmtree(folder_path, ignore_errors=True)
    folders.pop(folder_id, None)
    persist_state(["folders"])
    audit(username, "delete_folder", metadata={"folder_id": folder_id})
    return jsonify({"message": "Carpeta eliminada"})


@app.route("/web/folders/<folder_id>/delete", methods=["POST"])
@auth_required
def delete_folder_web(folder_id):
    username = get_current_username()
    current_user = users[username]
    folder = folder_for_user(folder_id, username)
    if not folder:
        set_notice("error", "Carpeta no disponible.")
        return redirect(url_for("dashboard"))
    if folder_id == users[username]["root_folder_id"] and current_user["role"] != "admin":
        set_notice("error", "No puedes eliminar la carpeta raiz.")
        return redirect(url_for("dashboard"))

    has_documents = any(document["folder_id"] == folder_id for document in documents.values())
    has_children = any(child["parent_id"] == folder_id for child in folders.values())
    if has_documents or has_children:
        set_notice("error", "La carpeta debe estar vacia para eliminarse.")
        return redirect(url_for("dashboard"))

    folder_path = UPLOADS_DIR / folder["owner"] / folder_id
    shutil.rmtree(folder_path, ignore_errors=True)
    folders.pop(folder_id, None)
    persist_state(["folders"])
    audit(username, "delete_folder", metadata={"folder_id": folder_id})
    set_notice("success", "Carpeta eliminada correctamente.")
    return redirect(url_for("dashboard"))


@app.route("/history", methods=["GET"])
@auth_required
def history():
    username = get_current_username()
    requested_user = request.args.get("user", username)
    current_user = users[username]
    if requested_user != username and current_user["role"] != "admin":
        return jsonify({"error": "No puede consultar historial ajeno"}), 403

    history_items = [entry for entry in audit_events if current_user["role"] == "admin" or entry["actor"] == requested_user]
    return jsonify(history_items)


@app.route("/backup", methods=["POST"])
@auth_required
def backup():
    username = get_current_username()
    backup_base = BACKUPS_DIR / f"backup_{username}_{utc_now().strftime('%Y%m%d_%H%M%S')}"
    source_dir = (UPLOADS_DIR / username).resolve()
    archive_path = shutil.make_archive(str(backup_base), "zip", root_dir=str(source_dir))
    audit(username, "backup", metadata={"archive": archive_path})
    if wants_html_response() or is_form_post():
        set_notice("success", "Backup generado correctamente.")
        return redirect(url_for("dashboard"))
    return jsonify({"message": "Backup generado", "archive": archive_path})


@app.route("/logs", methods=["GET"])
@admin_required
def logs():
    return jsonify(audit_events)


@app.route("/audit", methods=["GET"])
@admin_required
def audit_log():
    return jsonify(audit_events)


@app.route("/audit/url-check", methods=["POST"])
@auth_required
def audit_url_check():
    username = get_current_username()
    if request.is_json:
        data = require_json()
        target_url = (data.get("url") or "").strip()
    else:
        target_url = (request.form.get("url") or "").strip()

    if not is_public_url(target_url):
        audit(username, "url_check", status="blocked", metadata={"url": target_url})
        if wants_html_response() or is_form_post():
            set_notice("error", "URL bloqueada por politica SSRF.")
            return redirect(url_for("dashboard"))
        return jsonify({"error": "URL bloqueada por politica SSRF"}), 400

    try:
        with urllib.request.urlopen(target_url, timeout=3) as response:
            preview = response.read(200).decode("utf-8", errors="ignore")
            result = {
                "url": target_url,
                "status": response.status,
                "preview": preview,
            }
    except Exception as exc:
        audit(username, "url_check", status="failed", metadata={"url": target_url, "error": str(exc)})
        if wants_html_response() or is_form_post():
            set_notice("error", f"No fue posible consultar la URL: {exc}")
            return redirect(url_for("dashboard"))
        return jsonify({"error": "No fue posible consultar la URL", "detail": str(exc)}), 502

    audit(username, "url_check", metadata={"url": target_url, "status": result["status"]})
    if wants_html_response() or is_form_post():
        set_notice("success", f"URL validada correctamente. Estado HTTP {result['status']}.")
        return redirect(url_for("dashboard"))
    return jsonify(result)


@app.route("/admin", methods=["GET"])
@admin_required
def admin_panel():
    if wants_html_response():
        return redirect(url_for("dashboard") + "#admin")
    return jsonify({
        "users": [serialize_user(user) for user in users.values()],
        "sessions": [
            {
                "username": session_data["username"],
                "expires_at": session_data["expires_at"].isoformat(),
            }
            for session_data in sessions.values()
        ],
        "documents": [serialize_document(document) for document in documents.values()],
        "folders": [serialize_folder(folder) for folder in folders.values()],
        "events": audit_events[-100:],
        "sqlite": get_sqlite_summary(),
    })


@app.route("/search", methods=["GET"])
@auth_required
def search():
    username = get_current_username()
    query = request.args.get("q", "")
    extension = request.args.get("ext", "")
    owner = request.args.get("owner", "")
    results = visible_documents_for(username, query, extension, owner)
    audit(username, "search", metadata={"q": query, "ext": extension, "owner": owner})
    return jsonify([serialize_document(document) for document in results])


@app.route("/api/users", methods=["GET"])
@admin_required
def api_users():
    return jsonify([serialize_user(user) for user in users.values()])


@app.route("/api/files", methods=["GET"])
@auth_required
def api_files():
    username = get_current_username()
    return jsonify([
        serialize_document(document)
        for document in visible_documents_for(username)
    ])


@app.route("/api/folders", methods=["GET"])
@auth_required
def api_folders():
    username = get_current_username()
    role = users[username]["role"]
    return jsonify([
        serialize_folder(folder)
        for folder in folders.values()
        if role == "admin" or folder["owner"] == username
    ])


@app.route("/profile/<username>", methods=["GET"])
@auth_required
def profile(username):
    current_username = get_current_username()
    current_user = users[current_username]
    if username != current_username and current_user["role"] != "admin":
        return jsonify({"error": "No puede consultar este perfil"}), 403
    user = users.get(username)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
    return jsonify(serialize_user(user))


@app.route("/export", methods=["GET"])
@admin_required
def export_metadata():
    payload = {
        "users": [serialize_user(user) for user in users.values()],
        "documents": [serialize_document(document) for document in documents.values()],
        "folders": [serialize_folder(folder) for folder in folders.values()],
        "generated_at": iso_now(),
    }
    export_path = EXPORTS_DIR / f"metadata_{utc_now().strftime('%Y%m%d_%H%M%S')}.json"
    export_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    audit(get_current_username(), "export_metadata", metadata={"path": str(export_path)})
    if wants_html_response():
        set_notice("success", f"Metadata exportada en {export_path.name}.")
        return redirect(url_for("dashboard") + "#admin")
    return jsonify({"message": "Exportacion generada", "file": str(export_path), "payload": payload})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False)
