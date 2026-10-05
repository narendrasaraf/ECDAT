"""Exercise the actual configured AI through the loopback demo API; retain evidence."""
import json
import time
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parents[1]

def main():
    output = ROOT / '.ecdat/acceptance/live-ai.json'
    report = {'status': 'running', 'started_at': time.time(), 'checks': []}
    def save():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    def check(name, condition):
        report['checks'].append({'check': name, 'passed': bool(condition)})
        save()
        if not condition: raise AssertionError(name)
    save()
    try:
        with httpx.Client(base_url='http://127.0.0.1:8000', timeout=510, trust_env=False) as client:
            auth = client.post('/api/auth/login', json={'username':'analyst','password':'demo-analyst-change-me'})
            auth.raise_for_status()
            client.headers['X-CSRF-Token'] = auth.json()['csrf_token']
            pid = (ROOT / '.ecdat/demo-project-id.txt').read_text().strip()
            before = client.get(f'/api/projects/{pid}/workspace').json()
            question = ('The supplier expects strict X25519MLKEM768 but the dated imported TLS observation says X25519. '
                        'Give competing evidence-cited explanations and one discriminating registered check. '
                        'Keep RSA certificate authentication separate and do not assume the old observation is current.')
            result = client.post(f'/api/projects/{pid}/investigations', json={'question': question})
            result.raise_for_status()
            record = result.json()
            for _ in range(10):
                if record.get('status') != 'busy': break
                time.sleep(2)
                result = client.post(f'/api/projects/{pid}/investigations', json={'question': question})
                result.raise_for_status()
                record = result.json()
            report['investigation'] = record
            check('real_provider_current_policy_output', record.get('status') == 'validated' and record.get('validation_version') == 'ecdat.ai.v4')
            check('competing_hypotheses', 2 <= len(record.get('hypotheses', [])) <= 3)
            evidence_ids = {row['id'] for row in before['evidence']}
            citations = record['citations'] + [c for h in record['hypotheses'] for c in h['citations']]
            check('citations_in_authorized_project', all(c['evidence_id'] in evidence_ids for c in citations))
            check('bounded_registered_check', record.get('suggested_check', {}).get('check_id') in {'compare-artifact-identity','refresh-lab-tls'})
            after = client.get(f'/api/projects/{pid}/workspace').json()
            check('no_ai_findings_or_approval_mutation', before['findings'] == after['findings'] and before['decisions'] == after['decisions'])
            # Run only the exact registered operation validated and retained by the server.
            job = client.post(f"/api/investigations/{record['id']}/checks", json={'check_id': record['suggested_check']['check_id']})
            job.raise_for_status()
            job_id = job.json()['id']
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                job_result = client.get('/api/jobs/' + job_id).json()
                if job_result['status'] in {'completed','failed','cancelled'}: break
                time.sleep(1)
            report['registered_job'] = job_result
            check('registered_check_executed', job_result['status'] == 'completed')
            workspace = client.get(f'/api/projects/{pid}/workspace').json()
            report['check_result'] = next((r for r in workspace['investigations'] if r.get('parent_id') == record['id']), None)
            check('investigation_history_preserved', report['check_result'] is not None and any(r['id'] == record['id'] for r in workspace['investigations']))
            report['status'] = 'automated_checks_passed'
            report['quality_review'] = 'Pending review of reasoning and citation entailment; automatic format checks do not establish truth.'
    except Exception as exc:
        report['status'] = 'failed'
        report['error'] = type(exc).__name__ + ': ' + str(exc)[:300]
        raise
    finally:
        report['finished_at'] = time.time()
        save()
        print(json.dumps({'status':report['status'],'report':str(output)}), flush=True)

if __name__ == '__main__': main()
