"""Default-deny, single-process remediation. No forced-kill fallback."""
import math
import os
import sys
import psutil
from configuration import parse_address, parse_network, validate_config
from network_monitor import process_identity

PROTECTED_NAMES = frozenset({
    'system', 'system idle process', 'registry', 'smss.exe', 'csrss.exe',
    'wininit.exe', 'winlogon.exe', 'lsass.exe', 'services.exe', 'svchost.exe',
    'init', 'systemd', 'sshd', 'sshd-session', 'login', 'sudo', 'su',
})


def confirmation_text(identity):
    return f"TERMINAR {identity['pid']} {identity['create_time']}"


def _valid_identity(identity, pid):
    return (
        isinstance(identity, dict) and type(pid) is int and pid > 4
        and identity.get('pid') == pid
        and type(identity.get('create_time')) in (int, float)
        and math.isfinite(identity['create_time']) and identity['create_time'] > 0
        and all(isinstance(identity.get(key), str) and identity[key].strip()
                for key in ('name', 'exe', 'username'))
    )


def remediate_process(finding, *, config, apply=False, confirmation=None):
    """Revalidate a blocked-destination observation before one SIGTERM.

    Unknown identity, unsupported OS, privilege, changed process/connection,
    missing confirmation and inspection errors all deny the operation.
    The apply branch is tested only with simulated psutil objects.
    """
    pid = finding.get('pid')

    def result(status, reason):
        return {'pid': pid, 'status': status, 'reason': reason}

    identity = finding.get('process_identity')
    if finding.get('rule') != 'blocked_destination' or not _valid_identity(identity, pid):
        return result('blocked', 'Se requiere bloqueo explícito e identidad completa.')
    if type(apply) is not bool:
        return result('blocked', 'apply debe ser un booleano explícito.')
    if apply and confirmation != confirmation_text(identity):
        return result('cancelled', 'Falta la confirmación exacta para este proceso.')
    # Windows terminate() is forceful too; only Linux is supported for apply.
    if sys.platform != 'linux':
        return result('blocked', 'Terminación deshabilitada en esta plataforma; use observación.')
    signal_attempted = False
    try:
        policy = validate_config(config)
        address = parse_address(finding.get('remote_ip'))
        port = finding.get('remote_port')
        if type(port) is not int or not 1 <= port <= 65535:
            return result('blocked', 'Destino incompleto.')
        if not any(address in parse_network(rule) for rule in policy['BLOCKED_IPS']):
            return result('blocked', 'El destino ya no está bloqueado por la política.')
        if os.geteuid() == 0:
            return result('blocked', 'La remediación no se ejecuta como root.')
        current = psutil.Process(os.getpid())
        protected_pids = {0, 1, 2, 3, 4, current.pid, os.getppid()}
        protected_pids.update(parent.pid for parent in current.parents())
        if pid in protected_pids:
            return result('blocked', 'Proceso del sistema, propio o antecesor protegido.')
        process = psutil.Process(pid)
        if process_identity(process) != identity:
            return result('blocked', 'Identidad cambiada desde la detección; vuelva a escanear.')
        if identity['name'].casefold() in PROTECTED_NAMES:
            return result('blocked', 'Proceso crítico protegido.')
        uids = process.uids()
        if any(uid < 1000 or uid != os.geteuid() for uid in uids):
            return result('blocked', 'Solo se admiten procesos del mismo usuario sin privilegios.')
        if identity['username'] != current.username():
            return result('blocked', 'Propietario distinto.')
        if not any(conn.raddr and parse_address(conn.raddr.ip) == address
                   and conn.raddr.port == port for conn in process.net_connections(kind='inet')):
            return result('blocked', 'La conexión detectada ya no pertenece al proceso.')
        # Fresh object avoids cached exe/name/create_time across user confirmation.
        fresh = psutil.Process(pid)
        if process_identity(fresh) != identity or not process.is_running():
            return result('blocked', 'Proceso cambiado o finalizado antes de la acción.')
        if any(uid < 1000 or uid != os.geteuid() for uid in fresh.uids()):
            return result('blocked', 'Privilegios cambiados antes de la acción.')
        if not any(conn.raddr and parse_address(conn.raddr.ip) == address
                   and conn.raddr.port == port for conn in fresh.net_connections(kind='inet')):
            return result('blocked', 'Conexión desaparecida antes de la acción.')
        if not apply:
            return result('dry_run', 'Simulación: no se envió ninguna señal.')
        signal_attempted = True
        fresh.terminate()  # psutil also checks PID reuse before signalling.
        fresh.wait(timeout=3)
        return result('terminated', 'Finalización observada tras SIGTERM.')
    except KeyboardInterrupt:
        if signal_attempted:
            return result('interrupted', 'Intento de SIGTERM interrumpido; salida no confirmada. No se fuerza el cierre.')
        return result('cancelled', 'Inspección interrumpida antes de intentar señalizar.')
    except psutil.TimeoutExpired:
        return result('timeout', 'SIGTERM enviado; salida no confirmada. No se fuerza el cierre.')
    except (psutil.Error, OSError, ValueError, TypeError) as error:
        status = 'unconfirmed' if signal_attempted else 'blocked'
        return result(status, f'No se pudo verificar o completar la operación: {error}')


def kill_suspicious_process(pid):
    """Legacy PID-only calls are deliberately disabled; use the guarded API."""
    return False


def close_unauthorized_connection(pid):
    """Closing a connection must never implicitly kill its owning process."""
    return False
