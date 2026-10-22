import unittest
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch
import psutil
from configuration import validate_config
from network_monitor import scan_network


def connection(ip='8.8.8.8', pid=4242):
    return NS(laddr=NS(ip='192.0.2.1', port=1234),
              raddr=NS(ip=ip, port=443) if ip else (), status='ESTABLISHED', pid=pid)


class TestNetworkMonitor(unittest.TestCase):
    def setUp(self):
        self.net = patch('network_monitor.psutil.net_connections').start()
        self.process = patch('network_monitor.psutil.Process').start()
        self.addCleanup(patch.stopall)
        self.net.return_value = [connection()]
        proc = self.process.return_value
        proc.pid = 4242
        proc.create_time.return_value = 100.5
        proc.name.return_value = 'browser'
        proc.exe.return_value = '/opt/browser'
        proc.username.return_value = 'neo'
        proc.is_running.return_value = True

    def test_legitimate_internet_is_not_unauthorized_by_default(self):
        self.assertEqual(scan_network({}), [])

    def test_explicit_allowlist_miss_is_review_only(self):
        finding, = scan_network({'ENFORCE_ALLOWLIST': True})
        self.assertEqual(finding['rule'], 'outside_allowlist')
        self.assertFalse(finding['remediation_eligible'])

    def test_block_rule_has_reason_and_identity(self):
        finding, = scan_network({'BLOCKED_IPS': ['8.8.8.0/24']})
        self.assertEqual(finding['rule'], 'blocked_destination')
        self.assertEqual(finding['process_identity']['create_time'], 100.5)
        self.assertTrue(finding['remediation_eligible'])

    def test_block_takes_precedence_over_allow(self):
        finding, = scan_network({'BLOCKED_IPS': ['8.8.8.8'], 'AUTHORIZED_IPS': ['8.8.8.0/24']})
        self.assertEqual(finding['rule'], 'blocked_destination')

    def test_local_cidr_ipv6_and_listeners(self):
        for ip in ('127.0.0.2', '::1', '0:0:0:0:0:0:0:1', None):
            with self.subTest(ip=ip):
                self.net.return_value = [connection(ip)]
                self.assertEqual(scan_network({'ENFORCE_ALLOWLIST': True}), [])

    def test_ipv6_mapped_ipv4_cannot_bypass_block(self):
        self.net.return_value = [connection('::ffff:8.8.8.8')]
        self.assertEqual(scan_network({'BLOCKED_IPS': ['8.8.8.8']})[0]['rule'], 'blocked_destination')
        self.assertEqual(scan_network({'BLOCKED_IPS': ['::ffff:8.8.8.0/120']})[0]['rule'], 'blocked_destination')

    def test_missing_pid_and_inaccessible_identity_are_ineligible(self):
        for pid in (None, 4242):
            with self.subTest(pid=pid):
                self.net.return_value = [connection(pid=pid)]
                self.process.side_effect = psutil.AccessDenied(4242)
                finding, = scan_network({'BLOCKED_IPS': ['8.8.8.8']})
                self.assertFalse(finding['remediation_eligible'])
                self.assertIsNone(finding['process_identity'])

    def test_network_access_denied_is_not_empty_success(self):
        self.net.side_effect = psutil.AccessDenied()
        with self.assertRaises(psutil.AccessDenied):
            scan_network({})

    def test_invalid_remote_address_is_review_only(self):
        self.net.return_value = [connection('not-an-ip')]
        self.assertFalse(scan_network({})[0]['remediation_eligible'])

    def test_invalid_policy_fails_before_collection(self):
        for config in ([], {'ENFORCE_ALLOWLIST': 'false'}, {'BLOCKED_IPS': ['invalid']},
                       {'AUTHORIZED_IPS': '127.0.0.1'}, {'SUSPICIOUS_KEYWORDS': ['']},
                       {'ENFORCE_ALLOWLIST': True, 'AUTHORIZED_IPS': []}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                scan_network(config)
        self.net.assert_not_called()
