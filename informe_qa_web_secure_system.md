# Informe QA Formal

## 1. Datos generales
- Aplicacion evaluada: secure_system.py
- Entorno: local, Windows, Flask
- URL evaluada: http://127.0.0.1:5001
- Fecha de ejecucion: 27/05/2026
- Perfil de evaluacion: QA funcional
- Alcance: autenticacion, panel administrativo, restricciones por rol, visibilidad del bloque SQLite y consistencia visual del dashboard

## 2. Resumen ejecutivo
Se ejecuto una validacion funcional sobre la aplicacion web segura. Los flujos criticos revisados quedaron operativos: login de administrador, carga del dashboard, panel administrativo, restricciones de acceso para analista y visualizacion del bloque de estado SQLite.

Durante la revision se detecto una incidencia real en la interfaz: en la tabla de Estado SQLite, la columna Items mostraba un metodo interno de Python en lugar del conteo de elementos. La incidencia fue corregida y validada nuevamente en la misma sesion.

Tambien se detecto una incidencia operativa de entorno: habia una instancia antigua de Python escuchando en el puerto 5001 y sirviendo una version anterior de la aplicacion. Esa instancia fue detenida y reemplazada por la correcta del proyecto para completar la validacion sobre la version actual.

## 3. Casos probados

| ID | Caso probado | Resultado esperado | Resultado obtenido | Estado |
| --- | --- | --- | --- | --- |
| QA-01 | Acceso a landing page | La pagina principal debe responder y mostrar accesos a registro e inicio de sesion | La landing respondio correctamente y mostro opciones Crear cuenta e Iniciar sesion | Aprobado |
| QA-02 | Login con credenciales admin | El usuario admin debe autenticarse y acceder al dashboard | El login admin fue exitoso y redirigio al panel principal | Aprobado |
| QA-03 | Carga del dashboard administrativo | El dashboard debe mostrar secciones operativas del sistema | Se visualizaron busqueda, carga de archivos, carpetas, historial, API REST y panel admin | Aprobado |
| QA-04 | Visibilidad del panel admin para admin | El perfil admin debe ver el panel administrativo | El panel administrativo fue visible para admin | Aprobado |
| QA-05 | Visibilidad del bloque SQLite para admin | El perfil admin debe ver el bloque Estado SQLite y el enlace de navegacion asociado | La respuesta HTTP del dashboard incluyo Estado SQLite y el enlace #sqlite | Aprobado |
| QA-06 | Restriccion de panel admin para analista | El perfil analista no debe ver panel admin, gestion de usuarios ni bloque SQLite | La verificacion por HTTP confirmo que analista no visualiza esas secciones | Aprobado |
| QA-07 | Restriccion de acceso a /admin para analista | El perfil analista debe recibir acceso denegado al intentar entrar a /admin | La ruta /admin devolvio 403 para analista | Aprobado |
| QA-08 | Consistencia del HTML servido por la instancia correcta | El servidor en 5001 debe entregar la version actual del dashboard | Se confirmo por HTTP que el HTML servido incluye Estado SQLite y Gestion de usuarios | Aprobado |
| QA-09 | Integridad visual de la tabla Estado SQLite | La columna Items debe mostrar cantidades, no referencias internas del runtime | Inicialmente fallo: se mostraba el metodo interno de Python en la columna Items | Fallido y corregido |
| QA-10 | Revalidacion de la correccion de Items | Tras la correccion, la tabla Estado SQLite debe dejar de mostrar el metodo interno | La validacion final confirmo que el bug ya no aparece | Aprobado |

## 4. Evidencias

### QA-01 Landing page operativa
- Evidencia funcional: respuesta web correcta en la URL principal.
- Evidencia observada: titulo visible Secure Document Hub y accesos Crear cuenta e Iniciar sesion.

### QA-02 Login admin exitoso
- Evidencia funcional: autenticacion completada con credenciales demo admin / Admin1234.
- Evidencia observada: mensaje de sesion iniciada correctamente y acceso al dashboard.

### QA-03 Dashboard operativo
- Evidencia funcional: secciones visibles de documentos, operaciones, historial, API y gestion.
- Evidencia observada: dashboard con formularios de busqueda, carga, creacion de carpetas y panel administrativo.

### QA-04 Panel admin visible para admin
- Evidencia funcional: el dashboard admin mostro usuarios, sesiones y eventos.
- Evidencia observada: seccion Panel administrativo visible para el usuario administrador.

### QA-05 Bloque SQLite visible para admin
- Evidencia de verificacion HTTP:
  - HAS_SQLITE_TEXT=True
  - HAS_SQLITE_LINK=True
  - HAS_USER_MANAGEMENT=True
- Evidencia observada en navegador: enlace SQLite en el menu lateral y seccion Estado SQLite en el dashboard.

### QA-06 Restriccion visual para analista
- Evidencia de verificacion HTTP:
  - ANALYST_HAS_ADMIN_PANEL=False
  - ANALYST_HAS_USER_MANAGEMENT=False
  - ANALYST_HAS_SQLITE=False
- Resultado: el rol analista no visualiza bloques reservados a admin.

### QA-07 Restriccion de acceso a /admin
- Evidencia de verificacion HTTP:
  - ADMIN_STATUS=403
- Resultado: acceso administrativo correctamente restringido para analista.

### QA-08 Version correcta servida en el puerto 5001
- Evidencia de entorno:
  - Se detecto una instancia antigua de Python en el puerto 5001 que servia una version previa.
  - Se detuvo esa instancia y se levanto la correcta desde el entorno virtual del proyecto.
- Evidencia de revalidacion HTTP:
  - HAS_SQLITE_TEXT=True
  - HAS_SQLITE_LINK=True

### QA-09 Incidencia detectada en tabla SQLite
- Hallazgo: en la columna Items se mostraba una representacion interna tipo metodo de Python en lugar del conteo.
- Severidad QA: media.
- Impacto: defecto visual y de interpretacion de datos en panel admin.

### QA-10 Correccion validada
- Accion aplicada: ajuste en la plantilla para acceder al valor numerico por clave y no por atributo ambiguo.
- Evidencia de revalidacion HTTP:
  - HAS_SQLITE_TEXT=True
  - HAS_ITEMS_BUG=False

## 5. Incidencias detectadas

### INC-01 Tabla SQLite muestra valor incorrecto en Items
- Estado inicial: abierta
- Severidad: media
- Descripcion: la tabla de Estado SQLite mostraba una referencia interna de Python en vez del conteo de elementos persistidos.
- Causa: acceso ambiguo al campo items desde Jinja.
- Accion correctiva: ajuste de la plantilla para leer el valor por clave explicita.
- Estado final: corregida y validada.

### INC-02 Instancia antigua atendiendo el puerto 5001
- Estado inicial: abierta
- Severidad: media
- Descripcion: una instancia previa del interprete Python estaba sirviendo una version desactualizada de la aplicacion, lo que generaba diferencias entre el archivo actual y la web observada.
- Accion correctiva: detencion del proceso antiguo y levantamiento de la instancia correcta del proyecto.
- Estado final: corregida para esta sesion de pruebas.

## 6. Conclusiones QA
La aplicacion web se encuentra operativa para los flujos evaluados en esta revision. La autenticacion, el dashboard, el panel administrativo y la segregacion por roles funcionan de acuerdo con lo esperado en los casos probados.

Las dos incidencias encontradas durante la sesion quedaron controladas: una fue de entorno operativo y otra de representacion visual en el panel SQLite. Tras la correccion y revalidacion, no quedaron hallazgos abiertos dentro del alcance revisado.

## 7. Recomendaciones
1. Ejecutar una segunda ronda QA enfocada en subida, descarga, compartir y eliminacion de archivos desde navegador.
2. Agregar una matriz de casos de prueba regresivos para admin, analista y usuario comun.
3. Incluir evidencias visuales adicionales mediante capturas si el informe se usara como anexo academico o de auditoria.
