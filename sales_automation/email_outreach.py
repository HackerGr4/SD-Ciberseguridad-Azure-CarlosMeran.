"""Borradores locales para presentar una demostración educativa; no envía correo."""


def generate_email(client_name, scan_results=None):
    """Genera un borrador sin inferir infección, limpieza o criticidad.

    Conserva la interfaz anterior. Si se proporcionan datos, solo cambia el
    contexto del borrador: no verifica su origen ni interpreta sus contadores,
    incluidos los campos antiguos threats_found y threat_count.
    """
    subject = f"BORRADOR: Demostración educativa de observación de seguridad — {client_name}"

    if scan_results is None:
        context = (
            "Esta presentación describe una demostración con datos ficticios. "
            "No se ha realizado un análisis de tus equipos."
        )
    else:
        context = (
            "Se proporcionaron datos como contexto para este borrador. Su origen, "
            "alcance, reglas aplicadas y posibles errores deben revisarse antes "
            "de describir resultados. Este generador no verifica esos datos ni "
            "confirma que correspondan a un análisis de tus equipos."
        )

    body = f"""
Hola {client_name},

Te presento SD-Ciberseguridad-Azure-CarlosMeran., un prototipo educativo que muestra cómo registrar coincidencias con reglas configuradas y documentarlas para revisión humana.

{context}

La demo utiliza procesos, direcciones y archivos simulados y genera informes HTML y JSON. No inspecciona los procesos o conexiones del equipo ni ejecuta remediaciones reales.

Las coincidencias con reglas de red, patrones de texto o nombres de procesos no prueban infección. La ausencia de coincidencias tampoco demuestra que un equipo esté limpio. El prototipo no incluye firmas de malware verificadas; la cobertura de la observación fuera de la demo depende de permisos y plataforma.

Las pruebas automatizadas con datos simulados comprueban comportamiento programado; no acreditan eficacia de detección, cumplimiento normativo ni un servicio profesional de remediación. No se ofrecen limpieza, protección garantizada o plazos fijos.

El material disponible permite conocer el funcionamiento del prototipo y sus límites. Este borrador no incluye adjuntos ni acredita una revisión de seguridad de tu organización.

Saludos,
Proyecto SD-Ciberseguridad-Azure-CarlosMeran.

[Borrador de presentación educativa para revisión manual; no enviado.]
    """

    return {"subject": subject.strip(), "body": body.strip()}


if __name__ == "__main__":
    print("--- BORRADOR: PRESENTACIÓN DE LA DEMO ---")
    print(generate_email("Empresa de ejemplo (ficticia)")["body"])
    print("\n--- BORRADOR: DATOS DE EJEMPLO PROPORCIONADOS ---")
    print(generate_email("Empresa de ejemplo (ficticia)", {
        "schema_version": 2,
        "summary": {"network_policy_findings": 1},
        "client_name": "DEMOSTRACIÓN: DATOS SIMULADOS",
    })["body"])
