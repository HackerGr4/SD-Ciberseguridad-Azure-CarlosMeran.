import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from demo import run_demo


class TestDemo(unittest.TestCase):
    def test_complete_demo_only_uses_simulated_sources(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            output = Path(temp) / 'demo'
            self.assertEqual(run_demo(output), 0)
            report = json.loads((output / 'scan_report.json').read_text())
            self.assertIn('SIMULADOS', report['client_name'])
            self.assertEqual(report['summary']['network_policy_findings'], 1)
            self.assertEqual(report['summary']['signature_matches'], 0)
            self.assertEqual(report['details']['remediation_results'][0]['status'], 'dry_run')
            self.assertEqual(report['details']['scan_errors'], [])
            self.assertTrue((output / 'scan_report.html').is_file())
