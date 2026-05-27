# Comparativo Vulnerable vs Seguro

## Objetivo

Este documento compara la implementacion vulnerable del laboratorio con la nueva version corregida y funcional. La meta es mostrar que riesgos existian, como se corrigieron y que controles quedaron operativos en la nueva aplicacion.

## Archivos comparados

- Version vulnerable: `vulnerable_files.py`
- Version segura: `secure_system.py`

## Resumen General

La version vulnerable estaba diseñada para exponer fallas OWASP de forma intencional. La version segura mantiene las funciones principales del sistema documental, pero agrega validaciones, autenticacion robusta, autorizacion por usuario y recurso, registro seguro de eventos, mitigaciones para SSRF y Path Traversal, y una superficie administrativa con datos sanitizados.

## Comparacion por Area

| Area | Version vulnerable | Version segura |
|---|---|---|
| Registro | Acepta datos sin validar y puede sobrescribir usuarios | Valida username, email y password; impide duplicados |
| Passwords | Texto plano | Hash seguro con `generate_password_hash` |
| Login | Token predecible | Token aleatorio con expiracion |
| Sesiones | Sin vencimiento | Expiran automaticamente y se limpian |
| Control de acceso | Basado en headers manipulables o ausente | Decoradores `auth_required` y `admin_required` |
| Descarga de archivos | Sin autorizacion y vulnerable a traversal | Descarga por `document_id` con validacion de permisos y rutas |
| Subida de archivos | Usa nombre original sin sanitizar | Usa `secure_filename`, limite de tamano y extensiones permitidas |
| Eliminacion | Cualquiera puede borrar por nombre | Solo propietario o admin puede eliminar por `document_id` |
| Comparticion | Sin autenticacion real | Requiere usuario autenticado y controla permisos `read` o `write` |
| Carpetas | Sin validacion fuerte | Propietario, raiz protegida y borrado solo si esta vacia |
| Logs | Exponen informacion sensible | Auditoria sin secretos, acceso solo admin |
| Panel admin | Se falsifica con `Role: admin` | Requiere sesion real con rol admin |
| Exportacion | Expone usuarios y datos sensibles | Exporta metadatos sanitizados y solo admin |
| SSRF | Peticion remota sin controles | Valida esquema, hostname e IP publica antes de consultar |
| Path Traversal | Posible en subida, descarga y borrado | Rutas resueltas y validadas dentro de directorios permitidos |
| Configuracion | Debug activo y secreto debil | Debug desactivado y secreto configurable |

## Mejoras Implementadas en la Version Segura

### 1. Autenticacion mejorada

- Passwords protegidos con hashing.
- Tokens de sesion aleatorios y no predecibles.
- Expiracion de sesiones a 8 horas.
- Logout real con invalidacion del token.

### 2. Autorizacion por rol y por recurso

- Usuarios comunes solo acceden a sus propios recursos o a documentos compartidos.
- Administradores tienen acceso ampliado, pero no dependen de headers manipulables.
- Descarga, borrado, historial y perfiles verifican permisos antes de responder.

### 3. Manejo seguro de archivos

- Sanitizacion del nombre del archivo.
- Restriccion de extensiones permitidas.
- Limite de tamano de carga.
- Descarga por identificador y no por ruta libre.
- Validacion de rutas resueltas para evitar traversal.

### 4. Auditoria y logging seguro

- Registro de eventos relevante sin contrasenas ni tokens.
- Persistencia a archivo de log dentro de almacenamiento seguro.
- Consulta de logs limitada al rol administrador.

### 5. Mitigacion de SSRF

- Solo se aceptan URLs `http` o `https`.
- Se bloquean destinos privados, loopback, link local, multicast y reservados.
- Si la URL no cumple la politica, la solicitud se rechaza antes de abrir conexion.

### 6. Mejoras funcionales adicionales

- Interfaz inicial con diseño simple y panel de estado.
- API coherente por identificadores de documento.
- Exportacion segura de metadatos.
- Backup por usuario autenticado.
- Busqueda avanzada filtrada por permisos.

## Cobertura de Funciones del Sistema

La version segura implementa correctamente estas capacidades:

- Registro de usuarios.
- Login y gestion de sesiones.
- Subida y descarga de archivos.
- Compartir documentos.
- Panel administrativo.
- Historial de actividad.
- Gestion de carpetas.
- API REST.
- Auditoria.
- Busqueda avanzada.
- Eliminacion de archivos.
- Gestion de permisos.

## Vulnerabilidades Mitigadas

### Criticas mitigadas

- Passwords en texto plano.
- Tokens predecibles.
- Panel admin manipulable.
- Descarga no autorizada.
- Borrado no autorizado.
- Exportacion masiva de credenciales.
- Path Traversal.

### Medias mitigadas

- Falta de validacion de entrada.
- Sesiones persistentes sin control.
- Logs inseguros.
- Backup expuesto.
- Subida de archivos sin restricciones.

### Bajas mitigadas

- Errores por parametros nulos.
- Enumeracion amplia de recursos.

## Ejecucion de la Version Segura

Para ejecutar la version corregida se utiliza la aplicacion Flask contenida en `secure_system.py`. El servidor queda configurado para correr en localhost, puerto 5001, con debug desactivado.

Credenciales iniciales de prueba:

- Administrador: `admin` / `Admin1234`
- Usuario: `analista` / `Analista123`

## Conclusiones

La nueva implementacion no solo corrige las debilidades del laboratorio original, sino que tambien deja una base util para demostrar buenas practicas reales. La separacion entre version vulnerable y version segura permite mostrar claramente el proceso de remediacion, comparar decisiones de diseño y evidenciar el impacto tecnico de aplicar controles correctos.