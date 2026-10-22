import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import psutil
import main
from reporter import generate_html_report, generate_json_report
from setup_client import setup_client
from configuration import load_config
from test_remediation import finding, POLICY


class TestMain(unittest.TestCase):
    def setUp(self):
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)
        self.config = patch('main.load_config', return_value=POLICY | {'client_name': 'Neo', 'ENFORCE_ALLOWLIST': False}).start()
        self.network = patch('main.scan_network', return_value=[finding()]).start()
        self.files = patch('main.full_scan', return_value={'errors': [], 'suspicious_processes': [{'pid': 123, 'name': 'miner'}]}).start()
        self.json = patch('main.generate_json_report').start()
        self.html = patch('main.generate_html_report').start()
        self.action = patch('main.remediate_process', return_value={'pid': 4242, 'status': 'dry_run', 'reason': 'simulation'}).start()
        self.input = patch('builtins.input', return_value='').start()
        self.tty = patch('main.sys.stdin.isatty', return_value=True).start()
        patch('psutil.Process', side_effect=AssertionError('live Process forbidden')).start()
        patch('psutil.net_connections', side_effect=AssertionError('live connections forbidden')).start()
        patch('psutil.process_iter', side_effect=AssertionError('live processes forbidden')).start()
        self.addCleanup(patch.stopall)

    def test_default_cli_reports_without_remediation_or_input(self):
        self.assertEqual(main.main([]), 0)
        self.action.assert_not_called()
        self.input.assert_not_called()
        self.json.assert_called_once()
        self.html.assert_called_once()

    def test_dry_run_does_not_prompt_or_apply(self):
        self.assertEqual(main.main(['--review-remediation']), 0)
        self.assertNotIn('apply', self.action.call_args.kwargs)
        self.input.assert_not_called()

    def test_apply_requires_individual_prompts_and_deduplicates(self):
        a = finding()
        b = finding()
        b['pid'] = b['process_identity']['pid'] = 4243
        self.input.side_effect = ['TERMINAR 4242 100.5', '']
        main.review_remediation([a, a, b], POLICY, apply=True)
        self.assertEqual(self.input.call_count, 2)
        applies = [call for call in self.action.call_args_list if call.kwargs.get('apply')]
        self.assertEqual(len(applies), 2)
        self.assertEqual(applies[0].kwargs['confirmation'], 'TERMINAR 4242 100.5')
        self.assertEqual(applies[1].kwargs['confirmation'], '')

    def test_piped_input_is_never_approval(self):
        self.tty.return_value = False
        result = main.review_remediation([finding()], POLICY, apply=True)
        self.assertEqual(result[0]['status'], 'cancelled')
        self.input.assert_not_called()
        self.assertEqual(self.action.call_count, 1)  # preview only

    def test_eof_and_interrupt_cancel_rest(self):
        for error in (EOFError(), KeyboardInterrupt()):
            with self.subTest(error=error):
                self.action.reset_mock()
                self.input.side_effect = error
                b = finding()
                b['pid'] = b['process_identity']['pid'] = 4243
                results = main.review_remediation([finding(), b], POLICY, apply=True)
                self.assertEqual(results[-1]['status'], 'cancelled')
                self.assertEqual(self.action.call_count, 1)

    def test_incomplete_scan_disables_remediation(self):
        self.network.side_effect = psutil.AccessDenied()
        self.assertEqual(main.main(['--apply-remediation']), 1)
        self.action.assert_not_called()
        self.assertTrue(self.json.call_args.args[0]['scan_errors'])

    def test_invalid_config_stops_before_scan(self):
        self.config.side_effect = ValueError('bad config')
        self.assertEqual(main.main([]), 2)
        self.network.assert_not_called()
        self.action.assert_not_called()

    def test_name_only_findings_never_reach_remediation(self):
        self.network.return_value = []
        main.main(['--apply-remediation'])
        self.action.assert_not_called()

    def test_post_signal_interrupt_is_saved_and_stops_other_candidates(self):
        b = finding()
        b['pid'] = b['process_identity']['pid'] = 4243
        self.network.return_value = [finding(), b]
        self.action.side_effect = [
            {'pid': 4242, 'status': 'dry_run', 'reason': 'preview'},
            {'pid': 4242, 'status': 'interrupted', 'reason': 'signal attempted, exit unknown'},
        ]
        self.input.return_value = 'TERMINAR 4242 100.5'
        self.assertEqual(main.main(['--apply-remediation']), 0)
        self.assertEqual(self.action.call_count, 2)
        self.assertEqual(self.json.call_args.args[0]['remediation_results'][0]['status'], 'interrupted')
        self.assertEqual(self.html.call_args.args[0]['remediation_results'][0]['status'], 'interrupted')


class TestReportsAndConfig(unittest.TestCase):
    def test_report_escapes_all_untrusted_fields_and_limits_claims(self):
        payload = '<script>alert(1)</script>'
        with tempfile.TemporaryDirectory() as temp:
            data = {'client_name': payload, 'unauthorized_conns': [{'process_name': payload}],
                    'scan_errors': [payload], 'remediation_results': [{'reason': payload}]}
            path = Path(temp) / 'report.html'
            generate_html_report(data, path)
            content = path.read_text()
            self.assertNotIn(payload, content)
            self.assertIn('&lt;script&gt;', content)
            self.assertIn('ESCANEO INCOMPLETO', content)
            self.assertNotIn('SISTEMA SEGURO', content)
            self.assertNotIn('termine los procesos', content)
            generate_json_report(data, Path(temp) / 'report.json')
            self.assertIn('network_policy_findings', json.loads((Path(temp) / 'report.json').read_text())['summary'])

    def test_setup_is_safe_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'config.json'
            setup_client('Neo', ['192.0.2.0/24'], path)
            config = load_config(path)
            self.assertFalse(config['ENFORCE_ALLOWLIST'])
            self.assertEqual(config['BLOCKED_IPS'], [])
            with self.assertRaises(FileExistsError):
                setup_client('Other', config_path=path)
            self.assertEqual(load_config(path)['client_name'], 'Neo')
