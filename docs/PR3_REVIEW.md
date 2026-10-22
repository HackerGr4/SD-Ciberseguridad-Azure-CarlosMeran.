# Revisión técnica del PR #3

Revisión solicitada el 22 de octubre de 2026. Referencia inmutable inspeccionada:
`63dbac18a6f62bc456df71a68ff4237925bcccb0`, sobre
`b56e34e49ba6cb34cbf42ef747197334f72b85f7`. Se revisaron los 15 archivos añadidos,
sus llamadas y los archivos de configuración/documentación del repositorio.
No había AGENTS.md, SECURITY.md ni workflows en ese árbol. No se ejecutó el escáner
sobre equipos reales ni se realizaron remediaciones reales.

## Hallazgos y correcciones

1. **Alto — detección débil desembocaba en cierre de aplicaciones.**
   `network_monitor.scan_network` trataba cada destino no listado como no autorizado;
   `malware_scanner.get_running_processes` buscaba subcadenas de nombres.
   `main.main` reunía todos los PID y una sola respuesta autorizaba todo el lote.
   Ahora se usan reglas explícitas, indicios informativos separados y revisión por
   proceso. Nombres y ausencias de lista permitida no habilitan remediación.
2. **Alto — límite destructivo sin comprobaciones.**
   `remediation.kill_suspicious_process` admitía cualquier PID y `kill()` tras errores,
   incluso por permisos o desaparición. También existía el alias
   `close_unauthorized_connection`. Las entradas antiguas quedan inertes. La nueva
   API se niega por defecto y comprueba identidad, propietario, privilegios,
   procesos protegidos, conexión vigente y confirmación individual. No fuerza cierre.
3. **Medio — firma falsa.** El hash de `hello` figuraba como EICAR. Las firmas de
   demostración se retiraron del código de producción; solo se inyectan en pruebas.
4. **Medio — confianza excesiva e inyección HTML.** `client_name` se insertaba sin
   escape; el informe recomendaba terminar/borrar a partir de heurísticas y proclamaba
   “SISTEMA SEGURO”. Se escapa ese campo, se mantienen escapes en las tablas y se
   comunican reglas, incertidumbre, errores y resultados de remediación.
5. **Cobertura y configuración.** La configuración se valida al comenzar, sin I/O
   al importar módulos. Fallos de red/archivo/directorio no se presentan como ausencia
   de amenazas. Se mantiene reporte de observaciones aun con identidad inaccesible.

Se reprodujeron antes del parche, con mocks, una conexión legítima marcada, una
terminación sin confirmación y un timeout que disparaba `kill()` y devolvía éxito.
Las pruebas de regresión ahora rechazan esos comportamientos y preservan conexión
permitida/CIDR, reglas de bloqueo explícitas, observaciones heurísticas, generación
de informes y salida confirmada de un único proceso simulado autorizado.

## Validación reproducible

Entorno local: Linux, Python 3.12.14, psutil 6.0.0 (mínimo declarado).
Resultado: compilación correcta, 51 pruebas aprobadas, demo simulada correcta,
`pip check` sin conflictos y `git diff --check` sin errores.
La revisión independiente detectó pérdida del registro al interrumpir la espera
tras SIGTERM; se corrigió con resultado explícito no confirmado, parada de los
siguientes candidatos y pruebas de persistencia en ambos informes.

```sh
python -m compileall -q .
python -m unittest discover -v
python demo.py --output-dir CARPETA_NUEVA
git diff --check
```

La suite cubre datos simulados, decisiones del operador, cancelación/EOF/interrupción,
entrada no interactiva, PID reciclado, cambio tardío de identidad/privilegios/conexión,
PID propio/antecesor/crítico, permisos insuficientes, errores, timeout sin kill,
IPv4/IPv6/CIDR, falsa firma `hello`, informes y demo integral. No lanza procesos ni
abre conexiones para probar remediación. CI añade matriz Linux/Windows y Python
3.10/3.12, con permisos de lectura y acciones fijadas por SHA. El resultado remoto
debe comprobarse en Checks del PR; agregar un workflow no equivale a haberlo pasado.

## Condiciones para una demostración y para un servicio profesional

- **Demo del prototipo:** usar `demo.py`, datos ficticios y solo simulación. Mostrar
  tanto un control legítimo como una regla de bloqueo y explicar que el nombre de
  un proceso o una palabra clave no prueba infección. Verificar CI y revisar el
  reporte generado antes de presentarlo. No demostrar cierres en el equipo del cliente.
- **Detección defendible:** integrar y mantener fuentes de indicadores verificadas,
  registrar procedencia/fecha, comparar con un conjunto representativo de software
  benigno y casos controlados y medir falsos positivos y falsos negativos. La lista
  de firmas actual está vacía; no anunciar detección fiable de malware.
- **Robustez del escaneo:** presupuestos de tiempo/tamaño, lectura acotada de líneas,
  control de carreras/symlinks, archivos especiales, permisos parciales y volúmenes
  grandes. La comprobación de archivo regular no evita todas las carreras de archivos.
  La cobertura de procesos/conexiones depende de permisos y plataforma.
- **Remediación de producción:** pruebas de integración aprobadas en máquinas virtuales
  desechables y cuentas de prueba, política por plataforma, inventario de procesos
  críticos del cliente, protección con primitivas de identidad del SO cuando sea
  posible, registro duradero previo a actuar y recuperación. Las listas de nombres/UID
  son defensas conservadoras, no una clasificación completa de servicios críticos.
  SIGTERM también puede causar pérdida de trabajo. Windows sigue sin aplicación real.
- **Operación profesional:** alcance y autorización escrita, mínimos privilegios,
  confidencialidad/retención de informes, revisión humana y respaldo antes de cambios.
  Los informes locales se sobrescriben al repetir `main.py`; un registro inmutable y
  salidas exclusivas son necesarios antes de producción. No hay validación de Azure
  ni de infraestructura remota en esta herramienta.
- **Mensajes comerciales pendientes:** `STRATEGY_NEGOCIO.md`,
  `sales_automation/email_outreach.py` y `sales_automation/index.html` todavía contienen
  promesas de seguridad/tiempo/ingresos y urgencia no sustentadas. Se inspeccionaron,
  pero se dejó su reescritura fuera del parche de detección/remediación. No usarlos
  para ofrecer servicios hasta revisar sus afirmaciones y alcance.

No es una certificación de seguridad exhaustiva ni una aprobación para uso destructivo.
La infraestructura formal de escaneos de Codex Security y sus recursos auxiliares no
estaban disponibles en esta sesión; se realizó revisión directa de código, investigación
independiente y pruebas reproducibles, sin generar un identificador de escaneo formal.
