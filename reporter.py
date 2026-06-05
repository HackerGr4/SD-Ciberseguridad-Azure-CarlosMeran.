import json
import datetime

def generate_json_report(data, filename="scan_report.json"):
    """Saves scan data to a JSON file."""
    report = {
        "client_name": data.get("client_name", "Cliente Valorado"),
        "timestamp": datetime.datetime.now().isoformat(),
        "summary": {
            "unauthorized_connections": len(data.get('unauthorized_conns', [])),
            "malicious_files": len(data.get('malware_results', {}).get('malicious_files', [])),
            "suspicious_heuristics": len(data.get('malware_results', {}).get('suspicious_heuristics', [])),
            "suspicious_processes": len(data.get('malware_results', {}).get('suspicious_processes', []))
        },
        "details": data
    }
    with open(filename, 'w') as f:
        json.dump(report, f, indent=4)
    return filename

def generate_html_report(data, filename="scan_report.html"):
    """Generates a professional HTML report."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_name = data.get("client_name", "Cliente Valorado")

    unauthorized = data.get('unauthorized_conns', [])
    malicious = data.get('malware_results', {}).get('malicious_files', [])
    heuristics = data.get('malware_results', {}).get('suspicious_heuristics', [])
    processes = data.get('malware_results', {}).get('suspicious_processes', [])

    status_color = "#28a745" if not (unauthorized or malicious or heuristics or processes) else "#dc3545"
    status_text = "SISTEMA SEGURO" if status_color == "#28a745" else "ACCION REQUERIDA"

    html = f"""
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
            <ul>
                <li><strong>Conexiones no autorizadas:</strong> {len(unauthorized)}</li>
                <li><strong>Archivos maliciosos:</strong> {len(malicious)}</li>
                <li><strong>Alertas heurísticas:</strong> {len(heuristics)}</li>
                <li><strong>Procesos sospechosos:</strong> {len(processes)}</li>
            </ul>
        </div>

        <div class="section">
            <h2>Conexiones de Red</h2>
            {f'<div class="alert">Se detectaron {len(unauthorized)} conexiones externas no autorizadas.</div>' if unauthorized else '<div class="success">No se detectaron conexiones externas sospechosas.</div>'}
            {self_generate_table(unauthorized, ['process_name', 'pid', 'laddr', 'raddr', 'status']) if unauthorized else ''}
        </div>

        <div class="section">
            <h2>Análisis de Malware</h2>
            {f'<div class="alert">Se encontraron {len(malicious) + len(heuristics)} amenazas potenciales en el sistema.</div>' if (malicious or heuristics) else '<div class="success">No se encontraron archivos maliciosos.</div>'}

            {f"<h3>Coincidencias de Firma (Hash)</h3>" if malicious else ""}
            {self_generate_table(malicious, ['path', 'reason']) if malicious else ""}

            {f"<h3>Hallazgos Heurísticos</h3>" if heuristics else ""}
            {self_generate_table(heuristics, ['path', 'findings']) if heuristics else ""}
        </div>

        <div class="section">
            <h2>Procesos en Ejecución</h2>
            {f'<div class="alert">Se detectaron procesos con nombres sospechosos.</div>' if processes else '<div class="success">Todos los procesos analizados parecen legítimos.</div>'}
            {self_generate_table(processes, ['pid', 'name']) if processes else ''}
        </div>

        <div class="footer">
            <p>Este reporte fue generado automáticamente por SD-Ciberseguridad-Azure.</p>
            <p>Para soporte técnico o limpieza de sistemas, contacte a su administrador.</p>
        </div>
    </body>
    </html>
    """
    with open(filename, 'w') as f:
        f.write(html)
    return filename

def self_generate_table(items, keys):
    if not items: return ""
    header = "".join([f"<th>{k.replace('_', ' ').capitalize()}</th>" for k in keys])
    rows = ""
    for item in items:
        row = ""
        for k in keys:
            val = item.get(k, "N/A")
            if isinstance(val, list): val = ", ".join(val)
            row += f"<td>{val}</td>"
        rows += f"<tr>{row}</tr>"
    return f"<table><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table>"
