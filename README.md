# SD-Ciberseguridad-Azure-CarlosMeran

Prototipo de observación de seguridad para sistemas propios o expresamente autorizados.
No es un antivirus, una certificación ni una auditoría profesional completa. No incluye
una base verificada de firmas maliciosas. Los indicios necesitan corroboración humana.

## Instalación y pruebas

Python 3.10 o posterior. Cree un entorno virtual e instale `requirements.txt`.

```sh
python -m pip install -r requirements.txt
python -m unittest discover -v
python demo.py --output-dir demo-output
```

La demo funciona sin inspeccionar procesos o conexiones del equipo. Usa objetos
simulados, direcciones de documentación y archivos temporales; genera informes
marcados como **DATOS SIMULADOS** en una carpeta nueva. Se niega a sobrescribirla.
No solicita confirmaciones ni envía señales a procesos. Es la modalidad apropiada
para presentar este prototipo. El workflow valida Linux/Windows con Python 3.10/3.12.

## Observación de un directorio autorizado

```sh
python main.py --directory RUTA_AUTORIZADA --config config.json
```

El modo predeterminado solo recopila observaciones y escribe los informes
`scan_report.json` y `scan_report.html` en el directorio actual. No necesita aceptar
ninguna remediación. No elevar privilegios para una demostración. Los informes
contienen metadatos del equipo y no deben publicarse sin revisar y anonimizar.
Los errores de acceso se informan como cobertura incompleta; algunos sistemas
omiten conexiones no visibles sin emitir error, por lo que nunca se certifica limpieza.

## Política explícita

- `BLOCKED_IPS`: IP o CIDR que el operador decidió bloquear para ese entorno.
  Coincidir es un hallazgo de política, no una confirmación de malware. Vacío por defecto.
- `AUTHORIZED_IPS`: IP o CIDR permitidos. Solo restringe si `ENFORCE_ALLOWLIST` es
  `true`. Fuera de la lista significa revisión informativa y nunca habilita cierre.
- `ENFORCE_ALLOWLIST`: `false` por defecto. No se etiqueta todo Internet como hostil.
- `PROCESS_WATCHLIST`: coincidencia exacta de nombres, sin distinción de mayúsculas,
  siempre informativa. Vacía por defecto; un nombre puede ser falsificado.
- `SUSPICIOUS_KEYWORDS`: patrones de texto, también comunes en software legítimo.
  No autorizan borrado, cuarentena ni terminación.

Se admiten IPv4, IPv6 y CIDR estrictos; se normalizan IPv4 representadas en IPv6.
Un bloqueo explícito prevalece sobre la lista permitida. Configuración inválida o
inaccesible detiene el CLI antes de escanear. La ruta predeterminada está junto al
programa, no se carga silenciosamente una política desde cualquier directorio.
`setup_client` crea una política de observación y se niega a sobrescribir una existente.

## Remediación experimental

`--review-remediation` solo simula las comprobaciones. El opt-in independiente
`--apply-remediation` requiere terminal interactiva y la frase exacta
`TERMINAR <pid> <create_time>` para **cada** proceso. Enter, una respuesta diferente,
EOF o interrupción no autorizan el cierre. Terminar una aplicación puede perder
trabajo y afecta todas sus conexiones; no equivale a cerrar un puerto.

Solo se consideran conexiones a destinos explícitamente bloqueados y con identidad
completa capturada al observarlas. El límite compartido `remediate_process` exige
confirmación, PID + fecha de creación + nombre + ejecutable + propietario estables,
conexión aún presente y política coincidente. Repite comprobaciones tras confirmar.
Bloquea PID bajos, el propio proceso, antecesores, nombres críticos, root, cuentas
con UID menor de 1000 y procesos con UID real/efectivo/guardado distinto al operador.
Una denegación, identidad desconocida o escaneo incompleto impide remediar.
Las APIs antiguas que reciben solo un PID devuelven `False` sin realizar acciones.

La terminación real está deshabilitada fuera de Linux. En Windows, `psutil.terminate()`
también equivale a un cierre forzado; no se presenta como cierre suave.
En Linux solo se intenta SIGTERM y se espera salida: no existe fallback a `kill()`.
El timeout se informa como salida no confirmada, nunca como éxito.
Las comprobaciones de usuariospace reducen riesgos pero no son una garantía atómica
contra cambios del proceso. La prueba del camino de aplicación usa únicamente mocks.

Los informes JSON usan `schema_version: 2`: los contadores se llaman
`network_policy_findings` y `signature_matches`; `details.unauthorized_conns` y
`malicious_files` se conservan por compatibilidad, pero no implican malware confirmado.
Los resultados de remediación se registran en ambos informes. Los antiguos informes
de ejemplo se retiraron para no presentar conclusiones o datos de host obsoletos.

Consulte [la revisión técnica y las condiciones de uso profesional](docs/PR3_REVIEW.md).
