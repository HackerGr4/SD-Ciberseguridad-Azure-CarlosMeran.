# SD-Ciberseguridad-Azure-CarlosMeran.

## Presentación profesional del prototipo educativo

SD-Ciberseguridad-Azure-CarlosMeran. es un proyecto educativo que muestra cómo
aplicar reglas explícitas de observación y documentar sus coincidencias para
revisión humana. Su demostración utiliza datos ficticios y genera informes HTML y
JSON para explicar el funcionamiento del programa y sus límites.

El objetivo es desarrollar un proyecto tecnológico confiable, con afirmaciones
que puedan contrastarse con el código y las pruebas disponibles. La presentación
actual no ofrece un servicio de seguridad validado.

## Capacidades y límites verificables

| Aspecto | Capacidad actual | Límite de interpretación |
| --- | --- | --- |
| Reglas de red | Comparación con reglas IP y CIDR configuradas. | Una coincidencia de política no demuestra una conexión maliciosa ni robo de datos. No es monitoreo continuo. |
| Archivos y procesos | Coincidencias de patrones de texto y nombres configurados. | Los indicios pueden aparecer en software legítimo; no confirman infección. No se incluye una base de firmas de malware verificadas. |
| Informes | Salidas locales HTML y JSON con coincidencias y errores registrados. | No genera PDF ni acredita limpieza, seguridad o cumplimiento normativo. |
| Demostración | `demo.py` emplea procesos, direcciones y archivos simulados. | No inspecciona los procesos o conexiones del equipo ni ejecuta remediaciones reales. |
| Pruebas | Suite automatizada con datos simulados y mocks. | Verifica comportamiento programado, no eficacia de detección frente a malware real. |
| Observación fuera de la demo | Recopilación local en entornos propios o expresamente autorizados. | La visibilidad depende de permisos y plataforma. No valida Azure ni infraestructura remota. |
| Remediación experimental | Código con controles y pruebas de decisiones simuladas. | No acredita intervenciones de producción ni un servicio profesional de limpieza. |

La ausencia de coincidencias no demuestra que un equipo esté limpio. Los errores
registrados y las limitaciones de visibilidad deben acompañar cualquier explicación
de los resultados.

## Cómo presentar la demostración

1. Indicar al comienzo que los datos son ficticios y que la sesión tiene finalidad
   educativa.
2. Usar `demo.py` con una carpeta de salida nueva, según el README. No ejecutar una
   intervención sobre el equipo de un cliente para ilustrar la herramienta.
3. Mostrar una coincidencia de regla y un caso de control. Explicar por qué una
   coincidencia no equivale a malware confirmado.
4. Revisar los informes HTML y JSON y sus límites. No presentar sus contadores como
   número de infecciones, criticidad o demostración de cumplimiento.
5. Acordar el contenido de la sesión según el contexto, sin garantizar duración,
   protección, limpieza o resultados económicos.

## Diferencia respecto de un servicio de seguridad validado

Un servicio validado necesita evidencia adicional que este prototipo todavía no
aporta: indicadores con procedencia y mantenimiento verificables, evaluación con
casos representativos benignos y maliciosos controlados, métricas de falsos
positivos y falsos negativos, y pruebas de integración autorizadas por plataforma.
También requiere procedimientos operativos con alcance y autorización escritos,
protección de los datos, registro duradero de acciones, recuperación y revisión
humana. Estas condiciones no constituyen por sí solas una certificación.

El resultado de una suite simulada no sustituye esa evaluación. Por ello, la
demostración no debe venderse como antivirus, auditoría completa, certificación de
cumplimiento o remediación profesional.

## Exploración responsable de oportunidades

El proyecto puede servir como material de portafolio y como punto de partida para
explorar documentación técnica, organización de datos o formación introductoria,
con alcance acorde con las competencias demostradas. Esas posibilidades son
hipótesis por validar: no existen aquí evidencias de demanda, ventas o rentabilidad.

La preparación puede apoyarse en los materiales existentes y las herramientas
gratuitas disponibles, verificando sus condiciones antes de asumir costes. Cualquier
encargo requeriría definir sus entregables, precio y plazo por separado. No se
prometen ingresos, contratación, ahorro o retorno económico.

## Referencias del proyecto

- [README: instalación, demo y límites](../README.md).
- [Revisión técnica y condiciones pendientes del PR #3](PR3_REVIEW.md).
- [Desarrollo responsable y exploración de oportunidades](../STRATEGY_NEGOCIO.md).

Este documento describe el alcance educativo del prototipo; no certifica su
seguridad ni autoriza remediaciones reales o campañas comerciales.
