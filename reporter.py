import json
import datetime
import html

def generate_json_report(data, filename="scan_report.json"):
    """Saves scan data to a JSON file."""
    report = {
        "schema_version": 2,
        "client_name": data.get("client_name", "Cliente Valorado"),
        "timestamp": datetime.datetime.now().isoformat(),
        "summary": {
            "network_policy_findings": len(data.get('unauthorized_conns', [])),
            "signature_matches": len(data.get('malware_results', {}).get('malicious_files', [])),
            "suspicious_heuristics": len(data.get('malware_results', {}).get('suspicious_heuristics', [])),
            "suspicious_processes": len(data.get('malware_results', {}).get('suspicious_processes', []))
        },
        "details": data
    }
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4)
    return filename

def generate_html_report(data, filename="scan_report.html"):
    """Generates a professional HTML report."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_name = html.escape(str(data.get("client_name", "Cliente Valorado")))

    unauthorized = data.get('unauthorized_conns', [])
    malicious = data.get('malware_results', {}).get('malicious_files', [])
    heuristics = data.get('malware_results', {}).get('suspicious_heuristics', [])
    processes = data.get('malware_results', {}).get('suspicious_processes', [])

    errors = data.get('scan_errors', [])
    outcomes = data.get('remediation_results', [])
    status_color = "#28a745" if not (unauthorized or malicious or heuristics or processes) else "#dc3545"
    status_text = "SIN COINCIDENCIAS EN LAS REGLAS ACTIVAS" if status_color == "#28a745" else "HALLAZGOS PARA REVISIÓN"
    if errors:
        status_text, status_color = "ESCANEO INCOMPLETO", "#b45309"

    recommendations = []
    if unauthorized:
        recommendations.append("<strong>Revisión de política:</strong> Verifique el destino, la aplicación y las reglas acordadas. Una coincidencia no prueba malware ni autoriza terminar procesos.")
    if malicious or heuristics:
        recommendations.append("<strong>Revisión de archivos:</strong> Corrobore las coincidencias con fuentes confiables. Las palabras clave también aparecen en software legítimo; no elimine archivos basándose solo en estos indicios.")
    if processes:
        recommendations.append("<strong>Monitoreo de Procesos:</strong> Se están ejecutando procesos con nombres inusuales. Investigue el origen de estos binarios.")
    if not (unauthorized or malicious or heuristics or processes):
        recommendations.append("<strong>Mantenimiento:</strong> No hubo coincidencias con las reglas activas; esto no demuestra ausencia de amenazas. Continúe con escaneos regulares y mantenga su software actualizado.")

    recommendations_html = "".join([f"<li>{r}</li>" for r in recommendations])

    report_html = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Reporte de Auditoría de Ciberseguridad</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f4f7f6; }}
            .header {{ background-color: #343a40; color: white; padding: 20px; border-radius: 8px 8px 0 0; text-align: center; }}
            .status-banner {{ background-color: {status_color}; color: white; padding: 15px; text-align: center; font-weight: bold; font-size: 1.2em; }}
            .section {{ background: white; padding: 20px; margin-top: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            h2 {{ color: #007bff; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
            .alert {{ color: #721c24; background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; border-radius: 4px; margin-bottom: 10px; }}
            .success {{ color: #155724; background-color: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 4px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f8f9fa; }}
            .footer {{ text-align: center; margin-top: 30px; font-size: 0.8em; color: #777; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Auditoría de Seguridad Digital</h1>
            <p>Preparado para: <strong>{client_name}</strong></p>
            <p>Generado el: {now}</p>
        </div>

        <div class="status-banner">
            ESTADO FINAL: {status_text}
        </div>

        <div class="section">
            <h2>Resumen Ejecutivo</h2>
            <p>Herramienta experimental: no incluye una base de firmas de malware verificada. Las heurísticas pueden producir falsos positivos. Sin coincidencias no significa sistema seguro; la visibilidad depende de permisos y del sistema operativo.</p>
            <ul>
                <li><strong>Hallazgos de política de red:</strong> {len(unauthorized)}</li>
                <li><strong>Coincidencias de firma:</strong> {len(malicious)}</li>
                <li><strong>Alertas heurísticas:</strong> {len(heuristics)}</li>
                <li><strong>Procesos sospechosos:</strong> {len(processes)}</li>
            </ul>
        </div>

        <div class="section">
            <h2>Conexiones de Red</h2>
            {f'<div class="alert">Se detectaron {len(unauthorized)} coincidencias de política de red para revisar.</div>' if unauthorized else '<div class="success">Sin coincidencias de red con las reglas activas.</div>'}
            {self_generate_table(unauthorized, ['process_name', 'pid', 'laddr', 'raddr', 'rule', 'reason']) if unauthorized else ''}
        </div>

        <div class="section">
            <h2>Análisis de Malware</h2>
            {f'<div class="alert">Se encontraron {len(malicious) + len(heuristics)} coincidencias que requieren revisión.</div>' if (malicious or heuristics) else '<div class="success">Sin coincidencias de archivos con las reglas activas.</div>'}

            {f"<h3>Coincidencias de Firma (Hash)</h3>" if malicious else ""}
            {self_generate_table(malicious, ['path', 'reason']) if malicious else ""}

            {f"<h3>Hallazgos Heurísticos</h3>" if heuristics else ""}
            {self_generate_table(heuristics, ['path', 'findings']) if heuristics else ""}
        </div>

        <div class="section">
            <h2>Procesos en Ejecución</h2>
            {f'<div class="alert">Nombres presentes en una lista de revisión; no prueban malware.</div>' if processes else '<div class="success">Sin coincidencias de nombre con la lista de revisión.</div>'}
            {self_generate_table(processes, ['pid', 'name']) if processes else ''}
        </div>

        <div class="section">
            <h2>Recomendaciones de Seguridad</h2>
            <ul>
                {recommendations_html}
            </ul>
        </div>

        <div class="section">
            <h2>Limitaciones y errores</h2>
            {self_generate_table([{'error': error} for error in errors], ['error']) if errors else '<p>Sin errores registrados. La cobertura no es exhaustiva.</p>'}
            <h2>Revisión de remediación</h2>
            {self_generate_table(outcomes, ['pid', 'status', 'reason']) if outcomes else '<p>No se solicitó ninguna acción de remediación.</p>'}
        </div>
        <div class="footer">
            <p>Este reporte fue generado automáticamente por SD-Ciberseguridad-Azure.</p>
            <p>Para soporte técnico o limpieza de sistemas, contacte a su administrador.</p>
        </div>
    </body>
    </html>
    """
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(report_html)
    return filename

def self_generate_table(items, keys):
    if not items: return ""
    header = "".join([f"<th>{html.escape(k.replace('_', ' ').capitalize())}</th>" for k in keys])
    rows = ""
    for item in items:
        row = ""
        for k in keys:
            val = item.get(k, "N/A")
            if isinstance(val, list):
                val = ", ".join([str(v) for v in val])
            else:
                val = str(val)
            row += f"<td>{html.escape(val)}</td>"
        rows += f"<tr>{row}</tr>"
    return f"<table><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table>"
