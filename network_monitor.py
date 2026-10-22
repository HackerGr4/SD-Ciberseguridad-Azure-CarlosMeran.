"""Read-only network policy observations, never proof of malware."""
import psutil
from configuration import load_config, parse_address, parse_network, validate_config


def process_identity(process):
    """Use the same Process object and reject an exited/recycled identity."""
    identity = {
        'pid': process.pid,
        'create_time': process.create_time(),
        'name': process.name(),
        'exe': process.exe(),
        'username': process.username(),
    }
    if not process.is_running():
        raise psutil.NoSuchProcess(process.pid)
    return identity


def get_active_connections():
    # AccessDenied propagates: an incomplete scan must not look like a clean scan.
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        identity = None
        if conn.pid:
            try:
                identity = process_identity(psutil.Process(conn.pid))
            except (psutil.Error, OSError):
                pass  # Keep the observation, but make remediation ineligible.
        connections.append({
            'laddr': str(conn.laddr) if conn.laddr else 'N/A',
            'raddr': str(conn.raddr) if conn.raddr else 'LISTEN',
            'status': conn.status,
            'pid': conn.pid,
            'process_name': identity['name'] if identity else 'Unknown',
            'process_identity': identity,
            'remote_ip': conn.raddr.ip if conn.raddr else None,
            'remote_port': conn.raddr.port if conn.raddr else None,
        })
    return connections


def scan_network(config=None):
    """Return explicit policy findings, not every unlisted Internet destination.

    A block rule takes precedence. Allowlist misses are review-only and only
    enabled by an explicit policy. No rule match means no conclusion of safety.
    """
    policy = load_config() if config is None else validate_config(config)
    allowed = [parse_network(value) for value in policy['AUTHORIZED_IPS']]
    blocked = [parse_network(value) for value in policy['BLOCKED_IPS']]
    findings = []
    for conn in get_active_connections():
        if not conn['remote_ip']:
            continue
        try:
            address = parse_address(conn['remote_ip'])
        except ValueError:
            findings.append({**conn, 'rule': 'invalid_address', 'severity': 'info',
                             'reason': 'Dirección no interpretable; revisión manual.',
                             'remediation_eligible': False})
            continue
        rule = next((network for network in blocked if address in network), None)
        if rule is not None:
            findings.append({**conn, 'rule': 'blocked_destination', 'severity': 'review',
                             'reason': f'Coincidencia con bloqueo explícito {rule}; no prueba malware.',
                             'remediation_eligible': bool(conn.get('process_identity'))})
        elif policy['ENFORCE_ALLOWLIST'] and not any(address in network for network in allowed):
            findings.append({**conn, 'rule': 'outside_allowlist', 'severity': 'info',
                             'reason': 'Fuera de la política permitida; no prueba malware.',
                             'remediation_eligible': False})
    return findings


if __name__ == '__main__':
    for finding in scan_network():
        print(finding)
