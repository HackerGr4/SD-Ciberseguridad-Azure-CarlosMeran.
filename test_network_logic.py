import unittest
from unittest.mock import patch, MagicMock
from network_monitor import scan_network

class TestNetworkMonitor(unittest.TestCase):
    @patch('psutil.net_connections')
    @patch('psutil.Process')
    def test_scan_network_flags_unauthorized(self, mock_process, mock_net_conns):
        mock_conn = MagicMock()
        mock_conn.laddr = MagicMock(ip='192.168.1.5', port=1234)
        mock_conn.raddr = MagicMock(ip='8.8.8.8', port=443)
        mock_conn.status = 'ESTABLISHED'
        mock_conn.pid = 1234
        mock_net_conns.return_value = [mock_conn]

        mock_proc_instance = MagicMock()
        mock_proc_instance.name.return_value = "suspicious_process"
        mock_process.return_value = mock_proc_instance

        unauthorized = scan_network()
        self.assertEqual(len(unauthorized), 1)
        self.assertEqual(unauthorized[0]['remote_ip'], '8.8.8.8')

    @patch('psutil.net_connections')
    def test_scan_network_allows_authorized(self, mock_net_conns):
        mock_conn = MagicMock()
        mock_conn.laddr = MagicMock(ip='127.0.0.1', port=8080)
        mock_conn.raddr = MagicMock(ip='127.0.0.1', port=80)
        mock_conn.status = 'ESTABLISHED'
        mock_conn.pid = 5678
        mock_net_conns.return_value = [mock_conn]

        unauthorized = scan_network()
        self.assertEqual(len(unauthorized), 0)

if __name__ == '__main__':
    unittest.main()
