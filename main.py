import sys
import time
from network_monitor import scan_network
from malware_scanner import full_scan
from reporter import generate_json_report, generate_html_report

def print_header(title):
    print("\n" + "="*50)
    print(f" {title} ")
    print("="*50)

def main():
    print_header("ESCÁNER DE CIBERSEGURIDAD AVANZADO")
    print(f"Fecha y Hora: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # 1. Network Scan
    print_header("PASO 1: MONITOREO DE RED")
    print("Buscando conexiones no autorizadas...")
    unauthorized_conns = scan_network()

    if unauthorized_conns:
        print(f"[!] ALERTA: Se detectaron {len(unauthorized_conns)} conexiones NO AUTORIZADAS:")
        for conn in unauthorized_conns:
            print(f"    - Proceso: {conn['process_name']} (PID: {conn['pid']})")
            print(f"      Origen: {conn['laddr']} -> Destino: {conn['raddr']}")
    else:
        print("[+] Red segura: No se detectaron conexiones externas no autorizadas.")

    # 2. Malware Scan
    print_header("PASO 2: ESCANEO DE MALWARE")
    print("Analizando archivos y procesos en ejecución...")
    scan_results = full_scan(".")

    found_threats = False

    if scan_results['malicious_files']:
        found_threats = True
        print("[!] ARCHIVOS MALICIOSOS CONFIRMADOS:")
        for f in scan_results['malicious_files']:
            print(f"    - {f['path']} ({f['reason']})")

    if scan_results['suspicious_heuristics']:
        found_threats = True
        print("\n[?] ARCHIVOS SOSPECHOSOS (Heurística):")
        for f in scan_results['suspicious_heuristics']:
            print(f"    - {f['path']} (Patrones: {', '.join(f['findings'])})")

    if scan_results['suspicious_processes']:
        found_threats = True
        print("\n[!] PROCESOS SOSPECHOSOS:")
        for p in scan_results['suspicious_processes']:
            print(f"    - PID: {p['pid']} Nombre: {p['name']}")

    if not found_threats:
        print("[+] Sistema de archivos y procesos limpios.")

    # 3. Generate Reports
    print_header("PASO 3: GENERANDO REPORTES")

    # Try to load client name from config
    client_name = "Cliente Valorado"
    try:
        import json
        with open("config.json", "r") as f:
            cfg = json.load(f)
            client_name = cfg.get("client_name", client_name)
    except:
        pass

    report_data = {
        'client_name': client_name,
        'unauthorized_conns': unauthorized_conns,
        'malware_results': scan_results
    }

    json_path = generate_json_report(report_data)
    html_path = generate_html_report(report_data)

    print(f"[+] Reporte JSON generado: {json_path}")
    print(f"[+] Reporte HTML profesional generado: {html_path}")

    print_header("RESUMEN DEL ESCANEO")
    if unauthorized_conns or found_threats:
        print("ESTADO: ¡AMENAZAS DETECTADAS!")
        print("Se recomienda revisar los elementos marcados arriba.")
    else:
        print("ESTADO: SISTEMA SEGURO")
        print("No se encontraron anomalías en esta sesión.")
    print("="*50 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nEscaneo cancelado por el usuario.")
        sys.exit(0)
