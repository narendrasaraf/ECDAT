"""Run the authored ECDAT case through the real local API and independent verifier.

Requires an already-running demo API/controller. It never starts services, calls an
AI provider, reads private keys, or talks to a public chain. Reports contain public
authored evidence only. Run sequentially with other memory-heavy acceptance work.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')
    temporary.replace(path)


class Acceptance:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.state = args.state_dir.resolve()
        self.report_path = self.state / 'acceptance/end-to-end.json'
        self.run_id = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid4().hex[:8]
        self.folder = self.state / 'acceptance/runs' / self.run_id
        self.folder.mkdir(parents=True)
        self.report = {
            'schema': 'ecdat.acceptance-run.v1', 'run_id': self.run_id,
            'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'status': 'running', 'base_url': args.base_url,
            'scope': 'Authored local demonstration; no production target or public chain',
            'checks': [], 'artifacts': {},
            'limitations': [
                'Local ledger has no independently operated consensus.',
                'Trust pins are copied from this installation, not an external organization.',
                'AI and browser acceptance are separate runs; this script does not imply they passed.',
            ],
        }
        self.analyst = httpx.Client(base_url=args.base_url, timeout=45, follow_redirects=False, trust_env=False)
        self.reviewer = httpx.Client(base_url=args.base_url, timeout=45, follow_redirects=False, trust_env=False)
        self.save()

    def save(self):
        write_json(self.report_path, self.report)
        write_json(self.folder / 'report.json', self.report)

    def check(self, name: str, condition: bool, detail: object = None):
        self.report['checks'].append({'check': name, 'status': 'passed' if condition else 'failed', 'detail': detail})
        self.save()
        print(json.dumps({'check': name, 'status': 'passed' if condition else 'failed'}), flush=True)
        if not condition:
            raise AssertionError(name + ': ' + str(detail)[:1000])

    def api(self, client, method: str, path: str, expected: int = 200, **kwargs):
        response = client.request(method, path, **kwargs)
        if response.status_code != expected:
            raise RuntimeError(f'{method} {path}: expected {expected}, received {response.status_code}: {response.text[:1000]}')
        return response.json()

    def login(self, client, username: str):
        # Explicit, public demo credentials. Session cookies/tokens are never saved.
        identity = self.api(client, 'POST', '/api/auth/login', json={
            'username': username, 'password': f'demo-{username}-change-me',
        })
        client.headers['X-CSRF-Token'] = identity['csrf_token']
        return self.api(client, 'GET', '/api/auth/me')['user']

    def job(self, initial: dict):
        deadline = time.monotonic() + self.args.job_timeout
        job_id = initial['id']
        while True:
            current = self.api(self.analyst, 'GET', '/api/jobs/' + job_id)
            if current['status'] in {'completed', 'failed', 'cancelled'}:
                write_json(self.folder / ('job-' + job_id + '.json'), current)
                self.check('job_completed:' + current.get('kind', job_id), current['status'] == 'completed', current)
                return current
            if time.monotonic() >= deadline:
                raise TimeoutError(f'Job {job_id} did not finish: {current.get("message", current["status"])}')
            time.sleep(1)

    def workspace(self):
        return self.api(self.analyst, 'GET', f'/api/projects/{self.project_id}/workspace')

    def export_and_verify(self):
        receipt = self.api(self.analyst, 'POST', f'/api/projects/{self.project_id}/exports', json={})
        write_json(self.folder / 'export-receipt.json', receipt)
        bundle_response = self.analyst.get(receipt['download_url'])
        self.check('export_download', bundle_response.status_code == 200)
        bundle_path = self.folder / 'bundle.json'
        bundle_path.write_bytes(bundle_response.content)
        self.check('download_matches_receipt', hashlib.sha256(bundle_response.content).hexdigest() == receipt['raw_sha256'])
        bundle = bundle_response.json()
        self.check('official_cbom_schema', receipt['cbom_validation']['status'] == 'passed', receipt['cbom_validation'])
        self.report['artifacts'].update(bundle=str(bundle_path), export_receipt=str(self.folder / 'export-receipt.json'))
        self.report['bundle_digest'] = receipt['content_digest']
        self.save()
        anchor = self.api(self.analyst, 'POST', f'/api/exports/{receipt["id"]}/anchor', expected=202, json={})
        duplicate = self.api(self.analyst, 'POST', f'/api/exports/{receipt["id"]}/anchor', expected=202, json={})
        self.check('anchor_idempotency', anchor['id'] == duplicate['id'])
        job = self.job(anchor)
        self.check('actual_local_anchor', job['result']['anchor_status'] == 'included-local', job['result'])
        passport = self.api(self.analyst, 'GET', f'/api/exports/{receipt["id"]}/passport')
        passport_path = self.folder / 'passport.json'
        write_json(passport_path, passport)
        self.check('honest_chain_scope', passport['anchor']['finality'] == 'not_independent_consensus', passport['anchor'])

        # Only public enrollment/deployment pins are copied; never signing keys.
        chain_state = self.state / 'chain'
        for name in ('trust.json', 'deployment.json'):
            source = chain_state / name
            if not source.is_file():
                raise FileNotFoundError(f'Missing public verifier pin: {source}')
            shutil.copyfile(source, self.folder / name)
        self.report['artifacts'].update(passport=str(passport_path), trust=str(self.folder / 'trust.json'), deployment=str(self.folder / 'deployment.json'))
        self.save()
        command = [self.args.node, str(ROOT / 'packages/chain/scripts/verify-anchor.mjs'), str(bundle_path),
                   '--passport', str(passport_path), '--trust', str(self.folder / 'trust.json'),
                   '--deployment', str(self.folder / 'deployment.json'), '--state-dir', str(chain_state)]
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=150, check=False)
        try:
            verification = json.loads(process.stdout)
        except ValueError:
            verification = {'valid': False, 'error': 'Verifier returned invalid output', 'stderr': process.stderr[-1500:]}
        write_json(self.folder / 'independent-verification.json', verification)
        self.report['artifacts']['independent_verification'] = str(self.folder / 'independent-verification.json')
        self.check('independent_signature_merkle_chain_verification', process.returncode == 0 and verification.get('valid') is True and verification.get('chain_status') == 'checked', verification)
        # Replay is a separate process with no API client. Its own report explains
        # whether unsupported/protected snapshots prevent a complete replay.
        replay_command = [sys.executable, str(ROOT / 'scripts/replay.py'), str(bundle_path),
                          '--expected-digest', receipt['content_digest'], '--tls-lab', '--isolated', '--output', str(self.folder / 'replay.json')]
        replay = subprocess.run(replay_command, cwd=ROOT, capture_output=True, text=True, timeout=180, check=False)
        try:
            replay_result = json.loads(replay.stdout)
        except ValueError:
            replay_result = {'status': 'failed', 'error': replay.stderr[-1500:]}
        write_json(self.folder / 'replay.json', replay_result)
        self.report['artifacts']['replay'] = str(self.folder / 'replay.json')
        self.check('independent_replay_has_no_failed_checks', replay.returncode == 0 and replay_result.get('status') != 'failed', replay_result)

    def migration(self, artifact: dict, fallback: bool):
        label = 'allowed_fallback' if fallback else 'strict_hybrid'
        proposal = self.api(self.analyst, 'POST', f'/api/projects/{self.project_id}/proposals', json={
            'artifact_id': artifact['id'], 'recipe': 'tls-hybrid', 'fallback': fallback,
        })
        pid = proposal['id']
        blocked = self.analyst.post(f'/api/proposals/{pid}/execute', json={})
        self.check(label + ':unapproved_execution_rejected', blocked.status_code == 409)
        self_approval = self.analyst.post(f'/api/proposals/{pid}/decisions', json={'action': 'approve', 'reason': 'Negative control'})
        self.check(label + ':analyst_cannot_approve', self_approval.status_code == 403)
        decision = self.api(self.reviewer, 'POST', f'/api/proposals/{pid}/decisions', json={
            'action': 'approve', 'reason': 'Authored acceptance: reviewed exact scope, copied candidate, retained RSA residual, and ' + label + ' peer policy.',
        })
        self.check(label + ':different_authenticated_reviewer', decision['reviewer_id'] != proposal['author_id'] and decision['proposal_digest'] == proposal['proposal_digest'])
        execution = self.api(self.analyst, 'POST', f'/api/proposals/{pid}/execute', expected=202, json={})
        duplicate = self.api(self.analyst, 'POST', f'/api/proposals/{pid}/execute', expected=202, json={})
        self.check(label + ':execution_idempotency', duplicate['id'] == execution['id'])
        job = self.job(execution)
        verification = next(v for v in self.workspace()['verifications'] if v['id'] == job['result']['verification_id'])
        write_json(self.folder / (label + '.json'), {'proposal': proposal, 'decision': decision, 'verification': verification})
        self.report['artifacts'][label] = str(self.folder / (label + '.json'))
        self.check(label + ':all_acceptance_checks_passed', verification['status'] == 'passed' and all(c['status'] == 'passed' for c in verification['checks']), verification['checks'])
        self.check(label + ':residual_rsa_authentication_retained', any('RSA' in r for r in verification['residuals']), verification['residuals'])
        peer = verification['observation']['classical']
        self.check(label + ':measured_peer_policy', (peer.get('connected') is True and peer.get('group') == 'X25519' and peer.get('authorized') and peer.get('payload_ok')) if fallback else peer.get('connected') is False, peer)
        original = next(a for a in self.workspace()['artifacts'] if a['id'] == artifact['id'])
        self.check(label + ':original_manifest_unchanged', original['manifest'] == artifact['manifest'] and original['manifest_digest'] == artifact['manifest_digest'])
        return verification

    def capability_assessment(self, verification: dict):
        entry={'source':'Actual accepted TLS measurement from this acceptance run','scope':'Authored loopback peer and candidate only','verification_id':verification['id'],'max_latency_ms':5000}
        measured=self.api(self.analyst,'POST',f'/api/projects/{self.project_id}/assess',json={'capabilities':{'key_exchange':entry}})
        candidates=[row for row in self.workspace()['candidates'] if row.get('assessment_id')==measured['id'] and row['role']=='key_exchange']
        self.check('capability_assessment_bound_to_run',len(candidates)==1 and candidates[0]['id'] in measured['candidate_ids'])
        candidate=candidates[0]
        self.check('measured_scoped_hybrid_feasible',candidate['provenance']['verification_id']==verification['id'] and candidate['provenance']['scope']=='Registered authored loopback TLS laboratory' and any(row['algorithm']=='X25519MLKEM768' and row['status']=='feasible' for row in candidate['candidates']),candidate)
        blocked=self.api(self.analyst,'POST',f'/api/projects/{self.project_id}/assess',json={'capabilities':{'key_exchange':{**entry,'requires_hsm':True}}})
        blocked_candidate=next(row for row in self.workspace()['candidates'] if row.get('assessment_id')==blocked['id'] and row['role']=='key_exchange')
        self.check('measured_tls_does_not_invent_hsm_support',all(row['status']=='blocked' and 'hsm_support_unknown' in row['unknowns'] for row in blocked_candidate['candidates']),blocked_candidate)
        write_json(self.folder/'capability-assessment.json',{'measured':candidate,'hsm_unknown':blocked_candidate})
        self.report['artifacts']['capability_assessment']=str(self.folder/'capability-assessment.json')

    def run(self):
        try:
            self.report['health'] = self.api(self.analyst, 'GET', '/api/health')
            analyst, reviewer = self.login(self.analyst, 'analyst'), self.login(self.reviewer, 'reviewer')
            self.check('distinct_authenticated_sessions', analyst['id'] != reviewer['id'])
            project = self.api(self.analyst, 'POST', '/api/projects/demo', json={})
            self.project_id = project['id']
            self.report['project_id'] = self.project_id
            seeded_again = self.api(self.analyst, 'POST', '/api/projects/demo', json={})
            self.check('demo_seed_idempotency', seeded_again['id'] == self.project_id)
            if self.args.fresh_demo:
                previous_id=self.project_id
                project=self.api(self.analyst,'POST','/api/projects/demo?fresh=true',json={})
                self.project_id=project['id']
                self.report['project_id']=self.project_id
                self.check('fresh_demo_isolated',self.project_id!=previous_id)
            workspace = self.workspace()
            self.check('public_authored_project', workspace['project']['disclosure'] == 'public-demo')
            original = next(a for a in workspace['artifacts'] if a.get('authored_fixture') and not a.get('source_id'))
            self.report['original_artifact_id'] = original['id']
            if project.get('job_id'):
                self.job({'id': project['job_id']})
            scan = self.api(self.analyst, 'POST', f'/api/projects/{self.project_id}/scan', expected=202,
                            json={'artifact_id': original['id']}, headers={'Idempotency-Key': 'acceptance:' + self.run_id})
            self.job(scan)
            workspace = self.workspace()
            self.check('located_inventory_with_preserved_conflict', len(workspace['findings']) >= 4 and bool(workspace['conflicts']), {'findings': len(workspace['findings']), 'conflicts': len(workspace['conflicts'])})
            context = self.api(self.analyst, 'POST', f'/api/projects/{self.project_id}/context', json={
                'data_lifetime': [8, 12], 'migration_time': [2, 4], 'quantum_horizon': [8, 15],
                'source': 'Authored acceptance scenario intervals; not a quantum forecast',
            })
            assessment = self.api(self.analyst, 'POST', f'/api/projects/{self.project_id}/assess', json={})
            self.check('attributed_interval_scenario', assessment['context_id'] == context['id'] and assessment['status'] == 'scenario_dependent' and assessment['delta']['low'] == -5 and assessment['delta']['high'] == 8, assessment)
            tasks = [
                {'id': 'runtime', 'title': 'Shared runtime evidence', 'owner': 'Platform', 'depends_on': [], 'status': 'unknown'},
                {'id': 'payments', 'title': 'Payments migration', 'owner': 'Payments', 'depends_on': ['runtime'], 'status': 'pending'},
                {'id': 'gateway', 'title': 'Gateway migration', 'owner': 'Gateway', 'depends_on': ['runtime'], 'status': 'pending'},
            ]
            plan = self.api(self.analyst, 'POST', f'/api/projects/{self.project_id}/plan', json={'tasks': tasks})
            self.check('shared_prerequisite_and_blocker_propagation', len(plan['shared_dependencies']) == 1 and set(plan['blocked_task_ids']) == {'runtime', 'payments', 'gateway'}, plan)
            # Verify the protected mutation boundary against the running server.
            csrf = self.analyst.headers.pop('X-CSRF-Token')
            try:
                denied = self.analyst.post(f'/api/projects/{self.project_id}/assess', json={})
                self.check('missing_csrf_rejected', denied.status_code == 403)
            finally:
                self.analyst.headers['X-CSRF-Token'] = csrf
            strict=self.migration(original, fallback=False)
            self.migration(original, fallback=True)
            self.capability_assessment(strict)
            self.export_and_verify()
            self.report['status'] = 'passed'
        except Exception as exc:
            self.report['status'] = 'failed'
            self.report['error'] = {'type': type(exc).__name__, 'message': str(exc)[:2000]}
            raise
        finally:
            self.report['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            self.analyst.close()
            self.reviewer.close()
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='http://127.0.0.1:8000')
    parser.add_argument('--state-dir', type=Path, default=ROOT / '.ecdat')
    parser.add_argument('--job-timeout', type=int, default=300)
    parser.add_argument('--fresh-demo',action='store_true',help='Create a new authored case without historical scanner records')
    parser.add_argument('--node', default=os.getenv('ECDAT_NODE') or (str(Path.home() / '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe') if os.name == 'nt' else 'node'))
    args = parser.parse_args()
    target = urlsplit(args.base_url)
    if target.scheme != 'http' or target.hostname not in {'127.0.0.1', 'localhost', '::1'} or target.username or target.password or target.path not in {'', '/'} or target.query or target.fragment:
        parser.error('Only a loopback HTTP API origin is permitted for public demo credentials')
    if not 10 <= args.job_timeout <= 900:
        parser.error('Job timeout must be between 10 and 900 seconds')
    acceptance = Acceptance(args)
    try:
        acceptance.run()
    except Exception as exc:
        print(json.dumps({'status': 'failed', 'error': str(exc), 'report': str(acceptance.report_path)}), flush=True)
        return 1
    print(json.dumps({'status': 'passed', 'report': str(acceptance.report_path), 'run_id': acceptance.run_id}), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
