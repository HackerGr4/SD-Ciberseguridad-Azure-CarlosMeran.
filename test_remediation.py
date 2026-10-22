import unittest
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch
import psutil
import remediation as r

IDENTITY = {'pid': 4242, 'create_time': 100.5, 'name': 'lab-worker',
            'exe': '/opt/lab-worker', 'username': 'neo'}
POLICY = {'BLOCKED_IPS': ['203.0.113.0/24']}


def finding():
    return {'pid': 4242, 'process_identity': dict(IDENTITY), 'remote_ip': '203.0.113.5',
            'remote_port': 443, 'rule': 'blocked_destination',
            'remediation_eligible': True, 'reason': 'Explicit lab block rule'}


def fake_process(identity):
    process = MagicMock()
    process.pid = identity['pid']
    for key in ('create_time', 'name', 'exe', 'username'):
        getattr(process, key).return_value = identity[key]
    process.is_running.return_value = True
    process.uids.return_value = (1000, 1000, 1000)
    process.net_connections.return_value = [NS(raddr=NS(ip='203.0.113.5', port=443))]
    return process


class TestRemediation(unittest.TestCase):
    def setUp(self):
        self.target = fake_process(IDENTITY)
        self.current = MagicMock(pid=9000)
        self.current.parents.return_value = [NS(pid=8999), NS(pid=8998)]
        self.current.username.return_value = 'neo'
        self.factory = patch('remediation.psutil.Process', side_effect=lambda pid: self.current if pid == 9000 else self.target).start()
        patch('remediation.sys.platform', 'linux').start()
        patch('remediation.os.getpid', return_value=9000).start()
        patch('remediation.os.getppid', return_value=8999).start()
        self.uid = patch('remediation.os.geteuid', return_value=1000, create=True).start()
        # No live process/network enumeration is permitted in this suite.
        patch('psutil.net_connections', side_effect=AssertionError('live network forbidden')).start()
        patch('psutil.process_iter', side_effect=AssertionError('live processes forbidden')).start()
        self.addCleanup(patch.stopall)

    def apply(self, candidate=None, **kwargs):
        candidate = candidate or finding()
        return r.remediate_process(candidate, config=kwargs.pop('config', POLICY), apply=True,
                                   confirmation=kwargs.pop('confirmation', r.confirmation_text(candidate['process_identity'])), **kwargs)

    def assert_no_signal(self):
        self.target.terminate.assert_not_called()
        self.target.kill.assert_not_called()

    def test_default_dry_run_never_signals(self):
        self.assertEqual(r.remediate_process(finding(), config=POLICY)['status'], 'dry_run')
        self.assert_no_signal()

    def test_legacy_entrypoints_refuse_bare_pid(self):
        self.assertFalse(r.kill_suspicious_process(4242))
        self.assertFalse(r.close_unauthorized_connection(4242))
        self.factory.assert_not_called()
        self.assert_no_signal()

    def test_exact_confirmation_required(self):
        for response in (None, '', 's', 'yes', 'TERMINAR 4242', 'TERMINAR 4242 99'):
            with self.subTest(response=response):
                self.assertEqual(self.apply(confirmation=response)['status'], 'cancelled')
        self.factory.assert_not_called()
        self.assert_no_signal()

    def test_one_confirmed_target_terminates_and_waits_without_kill(self):
        self.assertEqual(self.apply()['status'], 'terminated')
        self.target.terminate.assert_called_once_with()
        self.target.wait.assert_called_once_with(timeout=3)
        self.target.kill.assert_not_called()

    def test_timeout_never_escalates_or_reports_success(self):
        self.target.wait.side_effect = psutil.TimeoutExpired(3)
        self.assertEqual(self.apply()['status'], 'timeout')
        self.target.kill.assert_not_called()

    def test_signal_failure_never_forces_kill(self):
        for error in (psutil.AccessDenied(4242), psutil.NoSuchProcess(4242)):
            with self.subTest(error=error):
                self.target.terminate.side_effect = error
                self.assertEqual(self.apply()['status'], 'unconfirmed')
        self.target.kill.assert_not_called()
        self.target.wait.assert_not_called()

    def test_missing_and_invalid_identity(self):
        for identity in (None, {}, {**IDENTITY, 'create_time': float('nan')},
                         {**IDENTITY, 'create_time': 0}, {**IDENTITY, 'exe': ''}):
            with self.subTest(identity=identity):
                candidate = {**finding(), 'process_identity': identity}
                self.assertEqual(r.remediate_process(candidate, config=POLICY, apply=True)['status'], 'blocked')
        self.assert_no_signal()

    def test_invalid_and_protected_pid(self):
        for pid in (None, False, -1, 0, 1, 4, '4242', 9000, 8999, 8998):
            with self.subTest(pid=pid):
                candidate = finding()
                candidate['pid'] = candidate['process_identity']['pid'] = pid
                self.assertEqual(self.apply(candidate)['status'], 'blocked')
        self.assert_no_signal()

    def test_name_and_allowlist_only_evidence_refused(self):
        for rule in ('outside_allowlist', 'process_name_watchlist', 'invalid_address'):
            with self.subTest(rule=rule):
                self.assertEqual(self.apply({**finding(), 'rule': rule})['status'], 'blocked')
        self.assert_no_signal()

    def test_reused_pid_or_changed_executable_or_owner(self):
        for attribute, value in (('create_time', 101), ('exe', '/opt/another'), ('username', 'other'), ('name', 'new')):
            with self.subTest(attribute=attribute):
                method = getattr(self.target, attribute)
                method.return_value = value
                self.assertEqual(self.apply()['status'], 'blocked')
                method.return_value = IDENTITY[attribute]
        self.assert_no_signal()

    def test_identity_change_at_final_check(self):
        replacement = fake_process({**IDENTITY, 'create_time': 102})
        self.factory.side_effect = [self.current, self.target, replacement]
        self.assertEqual(self.apply()['status'], 'blocked')
        replacement.terminate.assert_not_called()
        self.assert_no_signal()

    def test_disappeared_process_and_access_denied(self):
        for error in (psutil.NoSuchProcess(4242), psutil.AccessDenied(4242)):
            with self.subTest(error=error):
                self.target.exe.side_effect = error
                self.assertEqual(self.apply()['status'], 'blocked')
        self.assert_no_signal()

    def test_critical_process_is_protected(self):
        candidate = finding()
        candidate['process_identity']['name'] = 'sshd'
        self.target.name.return_value = 'sshd'
        self.assertEqual(self.apply(candidate)['status'], 'blocked')
        self.assert_no_signal()

    def test_privileged_other_user_and_root_execution_blocked(self):
        for uids in ((0, 0, 0), (1000, 0, 1000), (1001, 1001, 1001), (999, 999, 999)):
            with self.subTest(uids=uids):
                self.target.uids.return_value = uids
                self.assertEqual(self.apply()['status'], 'blocked')
        self.uid.return_value = 0
        self.assertEqual(self.apply()['status'], 'blocked')
        self.assert_no_signal()

    def test_ancestor_inspection_failure_denies(self):
        self.current.parents.side_effect = psutil.AccessDenied(9000)
        self.assertEqual(self.apply()['status'], 'blocked')
        self.assert_no_signal()

    def test_stale_connection_or_policy_denies(self):
        self.assertEqual(self.apply(config={})['status'], 'blocked')
        self.target.net_connections.return_value = []
        self.assertEqual(self.apply()['status'], 'blocked')
        self.assert_no_signal()

    def test_windows_terminate_alias_cannot_run(self):
        with patch('remediation.sys.platform', 'win32'):
            self.assertEqual(self.apply()['status'], 'blocked')
        self.assert_no_signal()

    def test_non_boolean_apply_denies(self):
        self.assertEqual(r.remediate_process(finding(), config=POLICY, apply='false')['status'], 'blocked')
        self.assert_no_signal()

    def test_privilege_change_at_final_check_denies(self):
        replacement = fake_process(IDENTITY)
        replacement.uids.return_value = (1000, 0, 1000)
        self.factory.side_effect = [self.current, self.target, replacement]
        self.assertEqual(self.apply()['status'], 'blocked')
        replacement.terminate.assert_not_called()
        self.assert_no_signal()

    def test_connection_change_at_final_check_denies(self):
        replacement = fake_process(IDENTITY)
        replacement.net_connections.return_value = []
        self.factory.side_effect = [self.current, self.target, replacement]
        self.assertEqual(self.apply()['status'], 'blocked')
        replacement.terminate.assert_not_called()
        self.assert_no_signal()

    def test_interrupt_after_signal_has_explicit_unconfirmed_result(self):
        self.target.wait.side_effect = KeyboardInterrupt()
        self.assertEqual(self.apply()['status'], 'interrupted')
        self.target.terminate.assert_called_once_with()
        self.target.kill.assert_not_called()

    def test_interrupt_before_signal_cancels(self):
        self.target.exe.side_effect = KeyboardInterrupt()
        self.assertEqual(self.apply()['status'], 'cancelled')
        self.assert_no_signal()
