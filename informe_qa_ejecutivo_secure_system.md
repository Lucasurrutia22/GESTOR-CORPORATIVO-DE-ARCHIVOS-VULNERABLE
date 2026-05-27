# Informe Ejecutivo QA

## Evaluacion funcional de la aplicacion secure_system.py

### 1. Objetivo
Verificar el funcionamiento general de la aplicacion web segura desarrollada en secure_system.py, validando los flujos principales de acceso, panel administrativo, control por roles y visualizacion del estado de persistencia en SQLite.

### 2. Contexto de la evaluacion
- Aplicacion evaluada: secure_system.py
- Entorno: local, Windows, Flask
- URL evaluada: http://127.0.0.1:5001
- Fecha de evaluacion: 27/05/2026
- Tipo de prueba: QA funcional manual y validacion por HTTP local

### 3. Alcance
La evaluacion considero los siguientes puntos:
- Acceso a la pagina principal
- Inicio de sesion con perfil administrador
- Carga correcta del dashboard
- Visualizacion del panel administrativo
- Visualizacion del bloque de estado SQLite
- Restricciones del rol analista
- Restriccion de acceso a la ruta administrativa
- Revision de consistencia visual en el panel SQLite

### 4. Resultado general
La aplicacion aprobo los flujos principales evaluados. El sistema permitio autenticacion correcta, acceso al dashboard, visualizacion del panel administrativo para el perfil admin y restriccion adecuada para el perfil analista.

Durante la evaluacion se detectaron dos incidencias:
1. Un defecto visual en la tabla Estado SQLite.
2. Una incidencia operativa por existencia de una instancia antigua del servidor en el puerto 5001.

Ambas incidencias fueron corregidas y validadas nuevamente durante la misma sesion.

### 5. Sintesis de casos evaluados

| Caso | Resultado |
| --- | --- |
| Landing page accesible | Aprobado |
| Login con cuenta admin | Aprobado |
| Dashboard funcional | Aprobado |
| Panel admin visible para administrador | Aprobado |
| Bloque SQLite visible para admin | Aprobado |
| Restricciones visuales para analista | Aprobado |
| Acceso denegado a /admin para analista | Aprobado |
| Version correcta servida en el puerto 5001 | Aprobado |
| Correccion del bug visual en tabla SQLite | Aprobado |

### 6. Hallazgos relevantes

#### Hallazgo 1: defecto visual en tabla SQLite
En la tabla Estado SQLite, la columna Items mostraba un valor incorrecto asociado a una referencia interna de Python, en vez del numero de elementos persistidos.

- Impacto: confusion visual en el panel administrativo.
- Estado final: corregido y revalidado.

#### Hallazgo 2: instancia antigua del servidor
Durante la evaluacion se detecto que el puerto 5001 estaba siendo utilizado por una instancia previa del interprete Python, lo que provocaba que el navegador mostrara una version anterior de la aplicacion.

- Impacto: inconsistencia entre el codigo actual y la interfaz observada.
- Estado final: instancia antigua detenida y servidor correcto levantado.

### 7. Evidencias resumidas
- El dashboard admin mostro correctamente las secciones de gestion, historial y panel administrativo.
- La validacion HTTP confirmo la presencia de la seccion Estado SQLite en la version actual.
- La validacion HTTP confirmo que el perfil analista no visualiza el panel admin ni la seccion SQLite.
- La ruta /admin respondio con codigo 403 para el perfil analista.
- La revalidacion final confirmo que el error visual de la columna Items ya no aparece.

### 8. Conclusion
La aplicacion evaluada se encuentra operativa dentro del alcance revisado. Los controles funcionales principales se comportaron de forma correcta y la separacion de privilegios entre administrador y analista fue validada satisfactoriamente.

Las incidencias encontradas durante la evaluacion no quedaron pendientes: ambas fueron tratadas y verificadas en la misma sesion. En consecuencia, el estado final del sistema, dentro del alcance probado, es satisfactorio para efectos de entrega academica.

### 9. Recomendacion docente
Como mejora posterior a esta entrega, se recomienda ejecutar una segunda ronda de QA enfocada en operaciones documentales completas: subida, descarga, comparticion, eliminacion y pruebas de regresion por perfil de usuario.
