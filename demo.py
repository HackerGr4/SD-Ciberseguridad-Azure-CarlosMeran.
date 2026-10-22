"""Offline demonstration using only invented processes, IPs and temporary files."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch
import main


def run_demo(output_dir):
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    policy = {'client_name': 'DEMOSTRACIÓN: DATOS SIMULADOS', 'ENFORCE_ALLOWLIST': False,
              'BLOCKED_IPS': ['203.0.113.0/24'], 'PROCESS_WATCHLIST': ['lab-worker'],
              'SUSPICIOUS_KEYWORDS': ['eval(']}
    connection = NS(laddr=NS(ip='192.0.2.10', port=50000),
                    raddr=NS(ip='203.0.113.5', port=443), status='ESTABLISHED', pid=4242)
    ordinary = NS(laddr=NS(ip='192.0.2.10', port=50001),
                  raddr=NS(ip='198.51.100.5', port=443), status='ESTABLISHED', pid=None)
    worker = MagicMock(pid=4242)
    worker.name.return_value = 'lab-worker'
    worker.exe.return_value = '/simulated/lab-worker'
    worker.username.return_value = 'demo-user'
    worker.create_time.return_value = 100.5
    worker.is_running.return_value = True
    worker.uids.return_value = (1000, 1000, 1000)
    worker.net_connections.return_value = [connection]
    worker.terminate.side_effect = AssertionError('Demo must never signal any process')
    worker.kill.side_effect = AssertionError('Demo must never kill any process')
    current = MagicMock(pid=9000)
    current.parents.return_value = [NS(pid=8999)]
    current.username.return_value = 'demo-user'

    def process(pid):
        if pid == 4242:
            return worker
        if pid == 9000:
            return current
        raise AssertionError(f'Unexpected process access: {pid}')

    original_dir = Path.cwd()
    with tempfile.TemporaryDirectory() as fixtures, ExitStack() as stack:
        Path(fixtures, 'hello.txt').write_text('hello', encoding='utf-8')
        Path(fixtures, 'example.txt').write_text('Example documentation: eval(expression)', encoding='utf-8')
        stack.enter_context(patch('main.load_config', return_value=policy))
        stack.enter_context(patch('psutil.net_connections', return_value=[connection, ordinary]))
        stack.enter_context(patch('psutil.process_iter', return_value=[NS(info={'pid': 4242, 'name': 'lab-worker'})]))
        stack.enter_context(patch('psutil.Process', side_effect=process))
        stack.enter_context(patch('remediation.sys.platform', 'linux'))
        stack.enter_context(patch('remediation.os.getpid', return_value=9000))
        stack.enter_context(patch('remediation.os.getppid', return_value=8999))
        stack.enter_context(patch('remediation.os.geteuid', return_value=1000, create=True))
        try:
            os.chdir(output_dir)
            code = main.main(['--directory', fixtures, '--review-remediation'])
        finally:
            os.chdir(original_dir)
        worker.terminate.assert_not_called()
        worker.kill.assert_not_called()
    print(f'Demostración simulada: {output_dir}')
    return code


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', default='demo-output', help='Carpeta nueva para informes simulados.')
    args = parser.parse_args()
    raise SystemExit(run_demo(args.output_dir))
