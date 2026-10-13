"""Distinct capture/cleanup failures; simulated CLI is not real-model evidence."""

import importlib.util
import copy
import io
import json
import os
import runpy
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from codex_context import capture_tool_context, selected_event


class ManagedCoverageTests(unittest.TestCase):
    def test_verifies_extra_counts_and_preserves_unknown_fields(self):
        review = runpy.run_path(str(Path(__file__).with_name('review-model.py')))
        project = review['scope_with_verified_counts']
        expected = {'state': 'partial', 'issues': ['unreturned rows remain unknown']}
        original = {**expected, 'module_ref_count': 0, 'pinvoke_import_count': 2}
        scope, checks = project(original, expected, {'module_ref_count': 0, 'pinvoke_import_count': 2})
        self.assertEqual(scope, expected)
        self.assertTrue(all(checks.values()))
        self.assertEqual(original['pinvoke_import_count'], 2)
        for count in [3, '2', True]:
            scope, checks = project({**expected, 'pinvoke_import_count': count}, expected, {'pinvoke_import_count': 2})
            self.assertFalse(checks['pinvoke_import_count'])
        _, checks = project({**expected, 'module_ref_count': False}, {**expected, 'module_ref_count': 0}, {'module_ref_count': 0})
        self.assertFalse(checks['module_ref_count'])
        scope, _ = project({**expected, 'unsupported_claim': True}, expected, {})
        self.assertNotEqual(scope, expected)
        scope, _ = project({'state': 'partial', 'module_ref_count': 0}, expected, {'module_ref_count': 0})
        self.assertNotEqual(scope, expected)
        ambiguous = review['named_scope']({'native_boundaries': expected, 'native_boundary_declarations': {'state': 'complete'}}, ['native_boundaries', 'native_boundary_declarations'])
        scope, _ = project(ambiguous, expected, {'module_ref_count': 0})
        self.assertNotEqual(scope, expected)


class PcapCoverageTests(unittest.TestCase):
    def test_explicit_labels_preserve_original_nulls_and_source_scope(self):
        canonical = runpy.run_path(str(Path(__file__).with_name('review-model.py')))['pcap_observation_fields']
        original = {'outer_limitations': [], 'normalized_kind': 'pcap',
                    'normalized_coverage': {'examined': 2, 'total': 23, 'next_offset': 2, 'exhausted': False},
                    'normalized_source_coverage': 'partial', 'normalized_parent_evidence_id': None}
        result = canonical(original)
        self.assertEqual(result['limitations'], [])
        self.assertEqual(result['source_coverage'], 'partial')
        self.assertEqual(result['coverage']['total'], 23)
        self.assertIsNone(result['parent_evidence_id'])
        self.assertIn('outer_limitations', original)
        self.assertNotIn('parent_evidence_id', canonical({}))

    def test_conflicting_duplicates_and_json_type_substitutions_stay_failures(self):
        canonical = runpy.run_path(str(Path(__file__).with_name('review-model.py')))['pcap_observation_fields']
        for wrong in ['partial', None]:
            result = canonical({'normalized_source_coverage': 'complete', 'source_coverage': wrong})
            self.assertIn('conflicting_fields', result)
            self.assertEqual(result['normalized_source_coverage'], 'complete')
            self.assertEqual(result['source_coverage'], wrong)
        result = canonical({'normalized_coverage': {'examined': 1}, 'coverage': {'examined': True}})
        self.assertIn('conflicting_fields', result)
        self.assertEqual(canonical({'outer_limitations': [], 'limitations': []}), {'limitations': []})

    def test_unsupported_claims_are_retained_for_exact_producer_checking(self):
        canonical = runpy.run_path(str(Path(__file__).with_name('review-model.py')))['pcap_observation_fields']
        original = {'normalized_kind': 'pcap', 'unrecorded_traffic_absent': True}
        self.assertIn('unrecorded_traffic_absent', canonical(original))
        self.assertIsNone(canonical(None))


class PcapGraderWorkflowTests(unittest.TestCase):
    """Synthetic receipts test the grader boundary, not Wireshark or real models."""

    def fixture(self):
        parent, summary_id, page_id = ['ev_' + value * 64 for value in ['a', 'b', 'c']]
        capture = {'target': {'path': '/fixture/http.pcapng', 'sha256': 'd' * 64},
                   'capture_start': None, 'coverage': 'complete',
                   'retained_counts': {'http_request_uris': 3}}
        prefix = ['http://example.test/one', 'http://example.test/two']
        coverage = {'status': 'page', 'examined': 2, 'total': 3, 'next_offset': 2, 'exhausted': False}
        summary = {'evidence_id': summary_id, 'limitations': ['source', 'view'],
                   'normalized_result': {'kind': 'summary', 'view': {'kind': 'summary'},
                       'parent_operation': 'inspect_pcap_capture', 'parent_evidence_id': parent,
                       'summary': capture, 'coverage': {'status': 'complete-within-view', 'examined': 1, 'total': 1, 'next_offset': None, 'exhausted': True},
                       'limitations': ['source', 'view'], 'unknowns': ['unrecorded traffic']}}
        page = {'evidence_id': page_id, 'limitations': ['source', 'view'],
                'normalized_result': {'kind': 'pcap',
                    'view': {'kind': 'pcap', 'facet': 'http-uris', 'offset': 0, 'limit': 2},
                    'parent_operation': 'inspect_pcap_capture', 'parent_evidence_id': parent,
                    'page': {'facet': 'http-uris', 'items': prefix}, 'coverage': coverage,
                    'source_coverage': 'complete', 'artifact': capture['target'],
                    'limitations': ['source', 'view'], 'unknowns': ['unrecorded traffic']}}
        observations = [self.observation(value) for value in [summary, page]]
        reference = {'artifact_sha256': 'd' * 64, 'capture': capture,
                     'http_request_uris_first2': prefix, 'delivery_observations': observations}
        answer = copy.deepcopy({**reference, 'http_request_uris_first2': {
            'items': prefix, 'coverage': coverage, 'source_coverage': 'complete'},
            'evidence_ids': [summary_id, page_id]})
        return answer, [summary, page], copy.deepcopy(reference)

    def observation(self, record):
        value = record['normalized_result']
        return {'evidence_id': record['evidence_id'], 'limitations': record['limitations'],
                'kind': value['kind'], 'view': value['view'],
                'parent_evidence_id': value['parent_evidence_id'], 'coverage': value['coverage'],
                'unknowns': value['unknowns'], 'normalized_limitations': value['limitations']}

    def grade(self, answer, records, reference):
        review = runpy.run_path(str(Path(__file__).with_name('review-model.py')))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);trial = root / 'trial';trial.mkdir()
            for name, value in [('summary.json', {'completed_mcp_calls': []}),
                                ('trial-settings.json', {}), ('cleanup.json', {'profile_removed': True})]:
                (trial / name).write_text(json.dumps(value))
            (trial / 'answer.txt').write_text(json.dumps(answer))
            events = [{'type': 'item.completed', 'item': {'type': 'mcp_tool_call',
                       'tool': 'inspect_pcap_capture' if value['normalized_result']['kind'] == 'summary' else 'inspect_analysis_view',
                       'status': 'completed', 'result': {'structuredContent': value}}} for value in records]
            (trial / 'events.jsonl').write_text(''.join(json.dumps(value) + '\n' for value in events))
            source = root / 'reference';source.mkdir();(source / 'answer.json').write_text(json.dumps(reference))
            resource = root / 'resource.log'
            resource.write_text(json.dumps({'resource_scope': 'simulated-grader-only', 'abort': None,
                                           'resource_counters_verified': False, 'resource_events_final': None}) + '\n')
            output = root / 'review.json'
            argv = ['review-model.py', '--domain', 'pcap', '--trial', str(trial), '--reference', str(source),
                    '--resource-log', str(resource), '--output', str(output)]
            with patch.object(sys, 'argv', argv), patch('sys.stdout', io.StringIO()), self.assertRaises(SystemExit) as stopped:
                review['main']()
            self.assertEqual(stopped.exception.code, 1)  # Unknown resource counters stay false.
            return json.loads(output.read_text())

    def test_complete_grader_accepts_supported_receipts_and_equivalent_labels(self):
        answer, records, reference = self.fixture()
        self.assertTrue(self.grade(answer, records, reference)['all_factual_checks_pass'])
        for observation in answer['delivery_observations']:
            observation['outer_limitations'] = observation.pop('limitations')
            observation['normalized_coverage'] = observation.pop('coverage')
        self.assertTrue(self.grade(answer, records, reference)['all_factual_checks_pass'])

    def test_complete_grader_rejects_missing_nulls_bad_scope_and_malformed_identity(self):
        mutations = [lambda x: x['capture'].pop('capture_start'),
                     lambda x: x['http_request_uris_first2']['coverage'].__setitem__('exhausted', True),
                     lambda x: x['delivery_observations'][-1].__setitem__('evidence_id', {'unexpected': 'value'}),
                     lambda x: x['delivery_observations'][-1].__setitem__('unrecorded_traffic_absent', True)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                answer, records, reference = self.fixture();mutate(answer)
                self.assertFalse(self.grade(answer, records, reference)['all_factual_checks_pass'])

    def test_faithful_wrong_receipts_do_not_support_the_reported_uri_prefix(self):
        for wrong in ['facet', 'range', 'parent']:
            with self.subTest(wrong=wrong):
                answer, records, reference = self.fixture()
                page = copy.deepcopy(records[-1]);page['evidence_id'] = 'ev_' + 'e' * 64
                value = page['normalized_result']
                if wrong == 'facet':
                    value['view']['facet'] = 'endpoints'
                    value['page'] = {'facet': 'endpoints', 'items': [{'address': '127.0.0.1'}]}
                elif wrong == 'range':
                    value['view']['offset'] = 1
                    value['page']['items'] = ['http://example.test/two', 'http://example.test/three']
                else:
                    value['parent_evidence_id'] = 'ev_' + 'f' * 64
                records.append(page)
                answer['delivery_observations'][-1] = self.observation(page)
                answer['evidence_ids'][-1] = page['evidence_id']
                report = self.grade(answer, records, reference)
                self.assertTrue(report['factual_checks']['pcap_original_delivery_observations'])
                self.assertFalse(report['factual_checks']['pcap_cited_source_supports_uri_prefix'])
                self.assertFalse(report['all_factual_checks_pass'])


class ContextCaptureTests(unittest.TestCase):
    def test_filters_ambient_account_and_nested_usage_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / 'home'
            sessions = home / 'sessions'
            sessions.mkdir(parents=True)
            output = root / 'output'
            output.mkdir()
            events = [
                {'type': 'world_state', 'payload': {'state': {'env': 'ambient-marker'}}},
                {'type': 'session_meta', 'payload': {'creator_account_id': 'account-marker'}},
                {'type': 'response_item', 'payload': {
                    'type': 'custom_tool_call_output', 'call_id': 'original-call',
                    'output': 'caller-selected evidence and paths',
                    'internal_chat_message_metadata_passthrough': 'private-marker'}},
                {'type': 'token_usage_record', 'payload': {
                    'response_id': 'original-response', 'usage': {
                        'input_tokens': 12, 'cached_input_tokens': 4,
                        'environment': 'nested-ambient-marker'},
                    'transport_auth': 'auth-marker'}},
            ]
            (sessions / 'rollout.jsonl').write_text(''.join(json.dumps(x) + '\n' for x in events))
            (home / 'auth.json').write_text('copied-credential-marker')
            receipt = capture_tool_context(home, output)
            text = (output / 'codex-tool-context.jsonl').read_text()
            self.assertEqual(receipt['status'], 'captured')
            self.assertEqual(receipt['retained_events'], 2)
            for marker in ['ambient-marker', 'account-marker', 'private-marker',
                           'auth-marker', 'copied-credential-marker']:
                self.assertNotIn(marker, text)
            self.assertIn('caller-selected evidence and paths', text)
            self.assertIn('original-response', text)
            # Windows mode bits do not describe access control; this is a POSIX assertion.
            if os.name == 'posix':
                self.assertEqual((output / 'codex-tool-context.jsonl').stat().st_mode & 0o777, 0o600)

    def test_missing_rollouts_are_unknown_and_malformed_lines_remain_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'missing'
            output.mkdir()
            self.assertEqual(capture_tool_context(root / 'home', output)['status'], 'unavailable')
            sessions = root / 'home' / 'sessions'
            sessions.mkdir(parents=True)
            (sessions / 'rollout.jsonl').write_text('not-json\n' + json.dumps({
                'type': 'event_msg', 'payload': {'type': 'token_count', 'info': None}}) + '\n')
            partial = root / 'partial'
            partial.mkdir()
            receipt = capture_tool_context(root / 'home', partial)
            self.assertEqual(receipt['status'], 'partial')
            self.assertEqual(receipt['errors'][0]['line'], 1)
            self.assertEqual(receipt['retained_events'], 1)
        with self.assertRaises(ValueError):
            selected_event({'type': 'token_usage_record', 'payload': {'usage': {'input_tokens': True}}})
        with self.assertRaises(ValueError):
            selected_event({'type': {'environment': 'unexpected'}, 'payload': {}})
        with self.assertRaises(ValueError):
            selected_event({'type': 'response_item', 'timestamp': {'environment': 'unexpected'}, 'payload': {}})
        unknown = selected_event({'type': 'event_msg', 'payload': {'type': 'token_count', 'info': {'model_context_window': None}}})
        self.assertIsNone(unknown['payload']['info']['model_context_window'])

    def test_capture_failure_still_removes_trial_credentials_and_profile(self):
        spec = importlib.util.spec_from_file_location('agent_trial', Path(__file__).with_name('agent-trial.py'))
        agent = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(agent)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / 'runtime'
            (runtime / 'scripts').mkdir(parents=True)
            (runtime / 'scripts' / 'rea.mjs').write_text('')
            (runtime / 'package-lock.json').write_text('{}')
            auth_home = root / 'source-auth'
            auth_home.mkdir()
            (auth_home / 'auth.json').write_text('synthetic-credential')
            question = root / 'question.txt'
            question.write_text('Observe the declared fixture.')
            output = root / 'trial'
            child = Mock(stdin=io.StringIO())
            child.wait.return_value = 0
            arguments = ['agent-trial.py', '--runtime-root', str(runtime), '--revision', 'fixture',
                         '--prompt', str(question), '--output', str(output), '--capture-tool-context']
            with patch.dict(os.environ, {'CODEX_HOME': str(auth_home)}, clear=True), \
                    patch.object(sys, 'argv', arguments), \
                    patch.object(agent.shutil, 'which', return_value='/fixture/node'), \
                    patch.object(agent.subprocess, 'check_output', return_value='v24.18.0\n'), \
                    patch.object(agent.subprocess, 'Popen', return_value=child), \
                    patch.object(agent, 'capture_tool_context', side_effect=OSError('fixture capture failure')), \
                    patch.object(agent.Path, 'home', side_effect=AssertionError('Explicit CODEX_HOME must not resolve the default home')), \
                    patch('builtins.print'):
                with self.assertRaisesRegex(OSError, 'fixture capture failure'):
                    agent.main()
            self.assertFalse(list(output.glob('profile-*')))
            self.assertTrue(json.loads((output / 'cleanup.json').read_text())['profile_removed'])
            self.assertEqual((auth_home / 'auth.json').read_text(), 'synthetic-credential')

    def test_refuses_foreign_session_directory_and_symlink_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / 'home'
            home.mkdir()
            foreign = root / 'foreign'
            foreign.mkdir()
            (foreign / 'rollout.jsonl').write_text('private marker')
            (home / 'sessions').symlink_to(foreign, target_is_directory=True)
            output = root / 'directory-result'
            output.mkdir()
            receipt = capture_tool_context(home, output)
            self.assertEqual(receipt['status'], 'partial')
            self.assertEqual(receipt['retained_events'], 0)
            (home / 'sessions').unlink()
            (home / 'sessions').mkdir()
            (home / 'sessions' / 'linked.jsonl').symlink_to(foreign / 'rollout.jsonl')
            output = root / 'file-result'
            output.mkdir()
            receipt = capture_tool_context(home, output)
            self.assertEqual(receipt['status'], 'partial')
            self.assertEqual(receipt['errors'][0]['reason'], 'not_an_owned_regular_file')
            self.assertEqual((foreign / 'rollout.jsonl').read_text(), 'private marker')

    def test_guidance_requires_selected_tools_before_acquiring_a_profile(self):
        spec = importlib.util.spec_from_file_location('agent_trial', Path(__file__).with_name('agent-trial.py'))
        agent = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(agent)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'trial'
            arguments = ['agent-trial.py', '--runtime-root', str(root), '--revision', 'fixture',
                         '--prompt', str(root / 'question'), '--output', str(output), '--guide-enabled-tools']
            with patch.object(sys, 'argv', arguments), patch.object(sys, 'stderr', io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    agent.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
