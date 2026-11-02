# Desarrollo responsable y exploración de oportunidades

## Estado y alcance del proyecto

SD-Ciberseguridad-Azure-CarlosMeran. es un prototipo educativo de observación de
seguridad mediante reglas configuradas. Su presentación actual se limita a una
demostración con datos simulados y a explicar cómo interpretar sus informes.
No se ofrece como un servicio validado de detección o remediación.

El programa registra coincidencias de política de red, patrones de texto y nombres
de procesos para revisión humana. Genera informes locales en HTML y JSON. Una
coincidencia no confirma malware; la ausencia de coincidencias no acredita que un
equipo esté limpio. La cobertura depende de los permisos y del sistema operativo.
La herramienta no valida Azure ni infraestructura remota.

## Presentación y demostración

- Utilizar `demo.py` con sus datos ficticios, sin inspeccionar equipos de clientes
  ni demostrar cierres de procesos reales.
- Mostrar las reglas aplicadas, las coincidencias, los errores y los límites de
  cobertura. Explicar la diferencia entre una observación y una infección confirmada.
- Entregar, si se solicita, ejemplos HTML y JSON identificados como **DATOS
  SIMULADOS**. No anunciar exportación a PDF ni informes de cumplimiento.
- Describir los resultados como ejemplos del comportamiento del programa. Las
  pruebas automatizadas con mocks no miden eficacia frente a malware real.
- Acordar el contenido de cada demostración. No prometer una duración fija,
  entrega inmediata, protección, limpieza ni resultados económicos.

La presentación reutilizable está en
[Presentación del prototipo](docs/PRESENTACION_PROTOTIPO.md). Los requisitos técnicos
pendientes se documentan en [la revisión del PR #3](docs/PR3_REVIEW.md).

## Exploración de ingresos sin inversión inicial

Como hipótesis por validar, se pueden explorar servicios de documentación técnica,
organización de datos o explicación educativa de informes de ejemplo, con un
alcance acorde con las competencias demostradas. Son actividades distintas de
certificar seguridad o intervenir equipos. No se presupone demanda ni disposición
de pago, y este repositorio no acredita ventas o ingresos.

Para explorar esas opciones se pueden usar materiales existentes y herramientas
gratuitas disponibles. Cualquier coste o condición debe comprobarse antes de
asumirlo; no se requiere comprar publicidad, créditos o suscripciones para preparar
la demostración. Los precios, entregables y plazos se definirían por separado para
cada encargo, sin garantizar contratación, rentabilidad o ingresos.

`sales_automation/email_outreach.py` prepara únicamente borradores locales de
presentación educativa. Su nombre se conserva por compatibilidad. No envía correos
ni convierte observaciones en amenazas confirmadas o propuestas de limpieza.
Este plan no implica autorización para iniciar campañas comerciales.

## Requisitos antes de ofrecer un servicio de seguridad validado

El prototipo todavía no incluye firmas de malware verificadas ni métricas de
detección. Antes de plantear ese servicio se requiere, como mínimo:

1. Incorporar indicadores con procedencia y fecha verificables, y mantenerlos.
2. Evaluar casos benignos y maliciosos controlados con un conjunto representativo;
   documentar falsos positivos, falsos negativos y límites de cobertura.
3. Completar pruebas de integración autorizadas en máquinas virtuales desechables,
   por plataforma, incluyendo fallos, permisos y recuperación.
4. Validar límites de recursos, registro duradero de intervenciones y procedimientos
   operativos con alcance escrito, revisión humana y protección de los datos.

La remediación sigue siendo experimental. Sus protecciones y pruebas simuladas no
acreditan un servicio profesional de limpieza, cierre de puertos o recuperación.
Los informes actuales no certifican cumplimiento normativo. Cualquier evaluación
de cumplimiento requeriría un alcance, criterios y evidencias específicos.

Estas condiciones orientan el desarrollo; no constituyen una certificación ni
garantizan por sí solas la aptitud para producción.
