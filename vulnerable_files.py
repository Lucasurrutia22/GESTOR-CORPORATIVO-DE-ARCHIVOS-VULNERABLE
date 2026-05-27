from flask import Flask, request, jsonify, send_file
import os
import json
import shutil
import urllib.request
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key'
app.config['DEBUG'] = True

FILES_DIR = "files"
BACKUP_DIR = "backup"
EXPORT_DIR = "exports"

os.makedirs(FILES_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)

users = {
    "admin": {
        "password": "admin123",
        "role": "admin",
        "email": "admin@inacap.local"
    },
    "user": {
        "password": "1234",
        "role": "user",
        "email": "user@inacap.local"
    }
}

sessions = {}
activity_logs = []
documents = {}
folders = {
    "admin": ["admin"],
    "user": ["user"]
}
shares = []
audit_records = []


def ensure_user_folder(username):
    os.makedirs(os.path.join(FILES_DIR, username), exist_ok=True)


def log_event(user, action, details=None):
    activity_logs.append({
        "timestamp": datetime.utcnow().isoformat(),
        "user": user,
        "action": action,
        "details": details or {},
        "ip": request.remote_addr,
        "authorization": request.headers.get('Authorization')
    })


def get_user():
    token = request.headers.get('Authorization')
    if token in sessions:
        return sessions[token]
    return None


def get_role():
    header_role = request.headers.get('Role')
    if header_role:
        return header_role

    user = get_user()
    if user in users:
        return users[user].get('role', 'user')

    return 'guest'


for existing_user in users:
    ensure_user_folder(existing_user)


@app.route('/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data['username']
    password = data['password']
    role = data.get('role', 'user')

    users[username] = {
        "password": password,
        "role": role,
        "email": data.get('email', '')
    }
    folders.setdefault(username, [username])
    ensure_user_folder(username)

    log_event(username, 'register', {
        "password": password,
        "role": role,
        "payload": data
    })

    return jsonify({"message": "Usuario registrado", "user": users[username]})


@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data['username']
    password = data['password']

    if username in users and users[username]['password'] == password:
        token = f"{username}_token"
        sessions[token] = username
        log_event(username, 'login', {
            "password": password,
            "token": token
        })
        return jsonify({
            "token": token,
            "role": users[username]['role'],
            "profile": users[username]
        })

    log_event(username, 'failed_login', {"password": password})
    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')
    user = sessions.pop(token, None)
    log_event(user or 'anonymous', 'logout', {"token": token})
    return jsonify({"message": "Sesión cerrada"})


@app.route('/session', methods=['GET'])
def session_info():
    token = request.headers.get('Authorization')
    user = get_user()
    if not user:
        return jsonify({"error": "No autorizado"}), 401

    return jsonify({
        "token": token,
        "user": user,
        "profile": users.get(user),
        "folders": folders.get(user, [])
    })


@app.route('/upload', methods=['POST'])
def upload():
    user = get_user()
    if not user:
        return jsonify({"error": "No autorizado"}), 401

    file = request.files['file']
    folder = request.form.get('folder', user)
    save_dir = os.path.join(FILES_DIR, folder)
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, file.filename)
    file.save(save_path)

    document_id = str(len(documents) + 1)
    documents[document_id] = {
        "id": document_id,
        "name": file.filename,
        "path": save_path,
        "owner": user,
        "folder": folder,
        "shared_with": [],
        "permissions": {},
        "uploaded_at": datetime.utcnow().isoformat()
    }

    log_event(user, 'upload', {
        "file": file.filename,
        "folder": folder,
        "path": save_path
    })

    return jsonify({"message": "Archivo subido", "document": documents[document_id]})


@app.route('/files', methods=['GET'])
def list_files():
    output = []
    for root, _, filenames in os.walk(FILES_DIR):
        for filename in filenames:
            output.append(os.path.join(root, filename))
    return jsonify(output)


@app.route('/download')
def download():
    filename = request.args.get('file')
    path = os.path.join(FILES_DIR, filename)
    log_event(get_user() or 'anonymous', 'download', {
        "file": filename,
        "path": path
    })
    return send_file(path)


@app.route('/share', methods=['POST'])
def share():
    data = request.json or {}
    filename = data['filename']
    target = data['target']
    permission = data.get('permission', 'read')
    shared_by = get_user() or 'anonymous'

    shares.append({
        "filename": filename,
        "target": target,
        "permission": permission,
        "shared_by": shared_by
    })

    for document in documents.values():
        if document['name'] == filename:
            document['shared_with'].append(target)
            document['permissions'][target] = permission

    log_event(shared_by, 'share', data)

    return jsonify({
        "message": f"Archivo {filename} compartido con {target}",
        "permission": permission
    })


@app.route('/permissions', methods=['GET', 'POST'])
def permissions():
    if request.method == 'GET':
        return jsonify(shares)

    data = request.json or {}
    shares.append(data)
    log_event(get_user() or 'anonymous', 'permission_grant', data)
    return jsonify({"message": "Permiso actualizado", "data": data})


@app.route('/delete')
def delete():
    filename = request.args.get('file')
    path = os.path.join(FILES_DIR, filename)
    os.remove(path)
    log_event(get_user() or 'anonymous', 'delete', {
        "file": filename,
        "path": path
    })
    return jsonify({"message": "Archivo eliminado"})


@app.route('/folders', methods=['GET', 'POST', 'DELETE'])
def manage_folders():
    user = get_user() or request.args.get('user', 'anonymous')

    if request.method == 'GET':
        return jsonify({
            "user": user,
            "folders": folders.get(user, []),
            "all": folders
        })

    if request.method == 'POST':
        data = request.json or {}
        folder_name = data['folder']
        owner = data.get('owner', user)
        folders.setdefault(owner, []).append(folder_name)
        os.makedirs(os.path.join(FILES_DIR, folder_name), exist_ok=True)
        log_event(owner, 'folder_create', data)
        return jsonify({"message": "Carpeta creada", "folder": folder_name})

    folder_name = request.args.get('folder')
    shutil.rmtree(os.path.join(FILES_DIR, folder_name), ignore_errors=True)
    log_event(user, 'folder_delete', {"folder": folder_name})
    return jsonify({"message": "Carpeta eliminada", "folder": folder_name})


@app.route('/history')
def history():
    requested_user = request.args.get('user')
    role = get_role()

    if role == 'admin' and requested_user:
        return jsonify([entry for entry in activity_logs if entry['user'] == requested_user])

    current_user = get_user()
    return jsonify([
        entry for entry in activity_logs
        if entry['user'] == current_user or not current_user
    ])


@app.route('/backup')
def backup():
    source = request.args.get('source', FILES_DIR)
    target_name = request.args.get('name', 'files_backup')
    archive_path = shutil.make_archive(os.path.join(BACKUP_DIR, target_name), 'zip', source)
    log_event(get_user() or 'anonymous', 'backup', {
        "source": source,
        "archive": archive_path
    })
    return jsonify({"message": "Backup realizado", "archive": archive_path})


@app.route('/logs')
def logs():
    return jsonify(activity_logs)


@app.route('/audit', methods=['GET'])
def audit_log():
    return jsonify(audit_records)


@app.route('/audit/fetch', methods=['POST'])
def audit_fetch():
    data = request.json or {}
    url = data['url']
    response = urllib.request.urlopen(url)
    content = response.read(500).decode('utf-8', errors='ignore')

    record = {
        "url": url,
        "status": response.status,
        "content_preview": content,
        "requested_by": get_user() or 'anonymous'
    }
    audit_records.append(record)
    log_event(get_user() or 'anonymous', 'audit_fetch', record)

    return jsonify(record)


@app.route('/admin')
def admin_panel():
    role = request.headers.get('Role')
    if role == 'admin':
        return jsonify({
            "users": users,
            "sessions": sessions,
            "documents": documents,
            "folders": folders,
            "logs": activity_logs,
            "audit": audit_records,
            "shares": shares
        })

    return jsonify({"error": "No autorizado"}), 403


@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    owner = request.args.get('owner')
    extension = request.args.get('ext')

    results = []

    for root, _, filenames in os.walk(FILES_DIR):
        for filename in filenames:
            matches_keyword = keyword.lower() in filename.lower()
            matches_owner = not owner or owner in root
            matches_extension = not extension or filename.endswith(extension)

            if matches_keyword and matches_owner and matches_extension:
                results.append({
                    "file": filename,
                    "path": os.path.join(root, filename)
                })

    log_event(get_user() or 'anonymous', 'search', {
        "q": keyword,
        "owner": owner,
        "ext": extension
    })
    return jsonify(results)


@app.route('/api/users')
def api_users():
    return jsonify(users)


@app.route('/api/files')
def api_files():
    return jsonify(documents)


@app.route('/api/folders')
def api_folders():
    return jsonify(folders)


@app.route('/profile/<username>')
def profile(username):
    return jsonify(users.get(username, {}))


@app.route('/export')
def export_metadata():
    export_path = os.path.join(EXPORT_DIR, 'users_dump.json')
    with open(export_path, 'w', encoding='utf-8') as export_file:
        json.dump(users, export_file, indent=4)

    return json.dumps({
        "users": users,
        "documents": documents,
        "sessions": sessions,
        "export_path": export_path
    })


@app.route('/expose')
def expose_resources():
    return jsonify({
        "cwd": os.getcwd(),
        "files_dir": os.path.abspath(FILES_DIR),
        "backup_dir": os.path.abspath(BACKUP_DIR),
        "environment": dict(os.environ)
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
