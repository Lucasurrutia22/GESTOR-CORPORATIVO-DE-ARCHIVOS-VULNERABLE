# Analisis de Vulnerabilidades del Codigo Original

## Alcance

Este documento analiza la version original de `vulnerable_files.py` antes de las modificaciones posteriores. El objetivo es identificar todas las vulnerabilidades observables en el codigo inicial, clasificarlas por severidad y relacionarlas con OWASP Top 10.

## Resumen Ejecutivo

La version original presenta fallas criticas en autenticacion, autorizacion, manejo de archivos, exposicion de informacion, configuracion y logging. La aplicacion permite acceso indebido a recursos, almacenamiento de contrasenas en texto plano, path traversal, eliminacion arbitraria de archivos y exposicion de informacion sensible. En un entorno real, estas debilidades podrian derivar en compromiso total del sistema.

## Matriz de Vulnerabilidades

| ID | Vulnerabilidad | Ubicacion original | Severidad | OWASP | Impacto principal |
|---|---|---|---|---|---|
| 1 | Passwords en texto plano | Diccionario `users`, `register()`, `login()` | Alta | A07 | Compromiso de cuentas |
| 2 | Tokens de sesion predecibles | `login()` | Alta | A07 / A01 | Suplantacion de sesion |
| 3 | Sesiones sin expiracion ni proteccion | `sessions`, `get_user()` | Media | A07 | Persistencia indebida de acceso |
| 4 | Registro sin validacion de entrada | `register()` | Media | A03 | Corrupcion de datos, abuso funcional |
| 5 | Registro permite sobrescribir usuarios existentes | `register()` | Alta | A01 | Toma de cuentas |
| 6 | Ausencia de control de acceso en descarga | `download()` | Alta | A01 | Lectura no autorizada de archivos |
| 7 | Path Traversal en descarga | `download()` | Alta | A03 / A01 | Lectura arbitraria de archivos |
| 8 | Comparticion de archivos sin autenticacion | `share()` | Media | A01 | Acciones no autorizadas |
| 9 | Eliminacion de archivos sin autenticacion | `delete()` | Alta | A01 | Destruccion de informacion |
| 10 | Path Traversal en eliminacion | `delete()` | Alta | A03 / A01 | Borrado arbitrario de archivos |
| 11 | Backup sin autenticacion ni autorizacion | `backup()` | Media | A01 | Abuso de recursos, fuga de informacion |
| 12 | Logs inseguros accesibles sin control | `logs()` | Alta | A09 | Exposicion de actividad sensible |
| 13 | Panel admin basado en header manipulable | `admin_panel()` | Alta | A01 | Escalada a administrador |
| 14 | Exposicion de datos sensibles en panel admin | `admin_panel()` | Alta | A01 / A10 | Fuga de passwords y logs |
| 15 | Busqueda sin control de acceso | `search()` | Baja | A01 | Enumeracion de archivos |
| 16 | Posible denegacion por input nulo en busqueda | `search()` | Baja | A03 | Error de aplicacion |
| 17 | Exportacion completa de usuarios sin control | `export_metadata()` | Alta | A10 | Fuga masiva de informacion |
| 18 | Modo debug activo en produccion | `app.run(debug=True)` | Alta | A05 | Ejecucion remota, fuga de stack traces |
| 19 | Ausencia de validacion de nombre de archivo al subir | `upload()` | Alta | A03 | Escritura en rutas no previstas |
| 20 | Subida de archivos sin restricciones de tipo o tamano | `upload()` | Media | A05 / A03 | Carga de contenido malicioso |
| 21 | Falta de autorizacion por propietario del archivo | `upload()`, `download()`, `delete()`, `share()` | Alta | A01 | Acceso horizontal no autorizado |
| 22 | Falta de auditoria segura | `activity_logs` y rutas asociadas | Media | A09 | Trazabilidad deficiente y fuga de datos |

## Detalle de Vulnerabilidades

### 1. Passwords en texto plano

**Severidad:** Alta  
**OWASP:** A07 Identification and Authentication Failures

Las credenciales se almacenan directamente en memoria sin hashing. Esto ocurre tanto en la definicion inicial de usuarios como en el proceso de registro. Cualquier fuga de memoria, exportacion de datos o respuesta administrativa expone las contrasenas reales.

**Riesgo:** Compromiso inmediato de cuentas y reutilizacion de credenciales en otros servicios.

### 2. Tokens de sesion predecibles

**Severidad:** Alta  
**OWASP:** A07, A01

El token de sesion se construye concatenando el nombre del usuario con el sufijo `_token`. Un atacante puede adivinar el token de cualquier cuenta conocida sin necesidad de autenticarse.

**Riesgo:** Secuestro trivial de sesiones.

### 3. Sesiones sin expiracion ni controles adicionales

**Severidad:** Media  
**OWASP:** A07

Las sesiones no tienen expiracion, rotacion, invalidacion, firma criptografica ni asociacion a contexto de cliente. Una vez emitido un token, puede reutilizarse indefinidamente.

**Riesgo:** Reutilizacion prolongada de sesiones robadas.

### 4. Registro sin validacion de entrada

**Severidad:** Media  
**OWASP:** A03 Injection / Input inseguro

El registro no valida formato, longitud, caracteres permitidos ni presencia de campos opcionales. Admite datos arbitrarios, entradas vacias o estructuras inesperadas.

**Riesgo:** Inconsistencia de datos, abuso de logica y posibles fallas posteriores.

### 5. Registro permite sobrescribir usuarios existentes

**Severidad:** Alta  
**OWASP:** A01 Broken Access Control

La operacion de registro no verifica si el usuario ya existe. Un atacante podria registrar nuevamente `admin` o cualquier nombre existente y reemplazar la contrasena.

**Riesgo:** Toma completa de cuentas existentes.

### 6. Descarga de archivos sin autenticacion ni autorizacion

**Severidad:** Alta  
**OWASP:** A01 Broken Access Control

El endpoint de descarga no exige sesion ni valida propiedad, permisos o comparticion del recurso. Cualquier cliente puede solicitar cualquier archivo si conoce o adivina el nombre.

**Riesgo:** Exfiltracion de documentos.

### 7. Path Traversal en descarga

**Severidad:** Alta  
**OWASP:** A03, A01

La ruta se arma con `os.path.join(FILES_DIR, filename)` usando el parametro de usuario directamente. Esto permite secuencias como `../` para intentar acceder a archivos fuera del directorio previsto.

**Riesgo:** Lectura arbitraria de archivos del servidor.

### 8. Comparticion de archivos sin autenticacion

**Severidad:** Media  
**OWASP:** A01 Broken Access Control

El endpoint de comparticion acepta peticiones sin identificar al usuario que realiza la accion. Tampoco verifica existencia del archivo ni permisos previos.

**Riesgo:** Operaciones de negocio falsificadas y abuso funcional.

### 9. Eliminacion de archivos sin autenticacion

**Severidad:** Alta  
**OWASP:** A01 Broken Access Control

El endpoint de borrado permite eliminar archivos sin requerir autenticacion. No existe verificacion de rol, propietario o permiso.

**Riesgo:** Destruccion de informacion por cualquier actor remoto.

### 10. Path Traversal en eliminacion

**Severidad:** Alta  
**OWASP:** A03, A01

El borrado concatena directamente el nombre recibido con el directorio base y llama a `os.remove`. Un atacante podria intentar eliminar archivos fuera de la carpeta prevista mediante rutas relativas.

**Riesgo:** Borrado arbitrario de archivos del sistema o de la aplicacion.

### 11. Backup sin autenticacion ni autorizacion

**Severidad:** Media  
**OWASP:** A01 Broken Access Control

La generacion de backup esta expuesta sin ninguna validacion de identidad o privilegios. Cualquier usuario o atacante puede activar respaldos.

**Riesgo:** Consumo de recursos, abuso operacional y posible exposicion futura de respaldos.

### 12. Logs inseguros accesibles sin control

**Severidad:** Alta  
**OWASP:** A09 Security Logging and Monitoring Failures

La ruta de logs devuelve todo el historial de actividad sin autenticacion. Aunque el contenido original de cada evento es reducido, sigue exponiendo usuarios, archivos manipulados y trazas de actividad.

**Riesgo:** Enumeracion, inteligencia operativa y fuga de informacion sensible.

### 13. Panel administrativo basado en header manipulable

**Severidad:** Alta  
**OWASP:** A01 Broken Access Control

La autorizacion del panel admin depende exclusivamente del header `Role`. Un cliente puede enviar `Role: admin` y acceder sin ser realmente administrador.

**Riesgo:** Escalada vertical inmediata.

### 14. Exposicion de datos sensibles en panel admin

**Severidad:** Alta  
**OWASP:** A10 Server-Side Request Forgery no aplica; corresponde mejor a A01 y A02/A10 segun clasificacion del curso

El panel devuelve el diccionario completo de usuarios y los logs. Dado que las contrasenas estan en texto plano, la fuga es critica.

**Riesgo:** Divulgacion total de credenciales y actividad interna.

### 15. Busqueda sin control de acceso

**Severidad:** Baja  
**OWASP:** A01 Broken Access Control

La funcionalidad permite enumerar archivos sin requerir autenticacion. Aunque no entrega el contenido, facilita reconocimiento de recursos.

**Riesgo:** Reconocimiento previo a ataques posteriores.

### 16. Posible denegacion por input nulo en busqueda

**Severidad:** Baja  
**OWASP:** A03 Input inseguro

Si el parametro `q` no viene definido, la llamada a `keyword.lower()` provoca una excepcion. Esto puede usarse para causar errores repetidos.

**Riesgo:** Inestabilidad y revelacion de errores si debug esta activo.

### 17. Exportacion completa de usuarios sin control

**Severidad:** Alta  
**OWASP:** A10 Exposicion de recursos / datos sensibles

El endpoint exporta el contenido completo de `users` sin autenticacion ni filtrado. Esto incluye nombres de usuario, roles y passwords en texto plano.

**Riesgo:** Fuga masiva de credenciales.

### 18. Modo debug activo en produccion

**Severidad:** Alta  
**OWASP:** A05 Security Misconfiguration

La aplicacion se inicia con `debug=True`. En un despliegue inseguro, esto puede exponer trazas detalladas, variables internas e incluso una consola interactiva de depuracion.

**Riesgo:** Compromiso severo de la aplicacion y fuga de informacion sensible.

### 19. Ausencia de validacion del nombre de archivo al subir

**Severidad:** Alta  
**OWASP:** A03 Input inseguro

El archivo subido se guarda usando `file.filename` directamente. No se sanitiza el nombre ni se verifica si contiene rutas relativas, caracteres especiales o nombres peligrosos.

**Riesgo:** Escritura fuera del directorio esperado o sobreescritura de archivos.

### 20. Subida de archivos sin restricciones de tipo o tamano

**Severidad:** Media  
**OWASP:** A05 / A03

No hay validacion de extensiones, tipo MIME, contenido ni tamano maximo. Esto permite subir archivos potencialmente peligrosos o generar agotamiento de almacenamiento.

**Riesgo:** Carga de contenido malicioso y denegacion de servicio por almacenamiento.

### 21. Falta de autorizacion por propietario del archivo

**Severidad:** Alta  
**OWASP:** A01 Broken Access Control

La aplicacion no lleva relacion entre usuario y recurso al descargar, borrar o compartir. Incluso la subida no aplica segregacion por usuario. Cualquier autenticado, o incluso no autenticado en varias rutas, puede operar sobre recursos ajenos.

**Riesgo:** Acceso horizontal no autorizado y perdida de confidencialidad e integridad.

### 22. Falta de auditoria segura y monitoreo real

**Severidad:** Media  
**OWASP:** A09 Security Logging and Monitoring Failures

Aunque existe `activity_logs`, no se protege, no se persiste adecuadamente, no se filtra, no se controla acceso y no cubre eventos criticos con integridad. Ademas, los logs se exponen por API sin proteccion.

**Riesgo:** Dificultad para investigar incidentes y fuga adicional de informacion.

## Clasificacion por Severidad

## Alta

- Passwords en texto plano.
- Tokens de sesion predecibles.
- Registro que sobrescribe usuarios existentes.
- Descarga sin control de acceso.
- Path Traversal en descarga.
- Eliminacion sin control de acceso.
- Path Traversal en eliminacion.
- Logs accesibles sin control.
- Panel admin basado en header manipulable.
- Exposicion de datos sensibles en panel admin.
- Exportacion completa de usuarios.
- Debug activo.
- Falta de validacion del nombre de archivo en subida.
- Falta de autorizacion por propietario del archivo.

## Media

- Sesiones sin expiracion.
- Registro sin validacion.
- Comparticion sin autenticacion.
- Backup sin autorizacion.
- Subida sin restricciones de tipo o tamano.
- Auditoria insegura y monitoreo insuficiente.

## Baja

- Busqueda sin control de acceso para enumeracion.
- Error por parametro nulo en busqueda.

## Relacion con OWASP del Enunciado

### A01 Broken Access Control

Presente en panel admin, descarga, eliminacion, comparticion, backup, exportacion, busqueda y ausencia de autorizacion por propietario.

### A03 Input inseguro

Presente en uso directo de `username`, `password`, `file.filename`, `filename` y `q` sin validacion. Destacan los casos de Path Traversal y errores por input nulo.

### A05 Configuracion insegura

Presente principalmente en `debug=True` y en la falta de restricciones de subida de archivos.

### A07 Passwords plaintext

Presente en almacenamiento y comparacion directa de contrasenas, junto con gestion debil de sesiones.

### A09 Logs inseguros

Presente en exposicion abierta del historial de actividad y en la ausencia de logging seguro con control de acceso.

### A10 Exposicion de recursos

Presente en exportacion de usuarios, panel administrativo y acceso a archivos sin proteccion suficiente.

## Conclusiones

El codigo original era intencionalmente vulnerable y concentraba debilidades graves en casi todas las superficies relevantes: autenticacion, autorizacion, manejo de archivos, configuracion y exposicion de datos. La prioridad de remediacion, en un escenario real, deberia comenzar por:

1. Eliminar passwords en texto plano y aplicar hashing seguro.
2. Rehacer autenticacion y sesion con tokens aleatorios y expiracion.
3. Implementar autorizacion real por usuario, rol y recurso.
4. Sanitizar entradas y bloquear Path Traversal.
5. Cerrar debug, exportaciones y endpoints administrativos expuestos.
6. Reemplazar logging inseguro por auditoria segura.

## Nota de uso academico

Este documento sirve como evidencia para el trabajo del curso, especialmente para las tareas de identificar vulnerabilidades, clasificarlas segun OWASP y priorizar correcciones por severidad.