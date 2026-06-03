import psutil
import socket

# Whitelist of authorized remote IPs (example)
# In a real app, this might be loaded from a config file.
AUTHORIZED_IPS = [
    '127.0.0.1',  # Localhost
    '::1',        # IPv6 Localhost
    '0.0.0.0',    # Any interface (listening)
]

def get_active_connections():
    """Returns a list of active network connections."""
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "LISTEN"
            status = conn.status
            pid = conn.pid

            # Get process name if possible
            process_name = "Unknown"
            if pid:
                try:
                    process_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            connections.append({
                'laddr': laddr,
                'raddr': raddr,
                'status': status,
                'pid': pid,
                'process_name': process_name,
                'remote_ip': conn.raddr.ip if conn.raddr else None
            })
    except psutil.AccessDenied:
        print("Error: Access denied to network connections. Try running as sudo/admin.")

    return connections

def scan_network():
    """Scans for unauthorized network connections."""
    active_conns = get_active_connections()
    unauthorized = []

    for conn in active_conns:
        remote_ip = conn['remote_ip']
        if remote_ip and remote_ip not in AUTHORIZED_IPS:
            unauthorized.append(conn)

    return unauthorized

if __name__ == "__main__":
    print("Scanning for unauthorized connections...")
    unauthorized = scan_network()
    if unauthorized:
        print(f"ALERTA: Se han detectado {len(unauthorized)} conexiones no autorizadas:")
        for conn in unauthorized:
            print(f" - Proceso: {conn['process_name']} (PID: {conn['pid']})")
            print(f"   Local: {conn['laddr']} -> Remoto: {conn['raddr']} [{conn['status']}]")
    else:
        print("No se detectaron conexiones sospechosas.")
