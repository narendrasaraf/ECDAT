"""Check live scoped capability assessment using an existing real TLS record."""
import json
from datetime import datetime, timezone
from pathlib import Path
import httpx

ROOT=Path(__file__).resolve().parents[1]
report={'checked_at':datetime.now(timezone.utc).isoformat(),'status':'running','checks':[]}
output=ROOT/'.ecdat/acceptance/live-capabilities.json'

def check(name,condition):
    report['checks'].append({'check':name,'passed':bool(condition)})
    if not condition:raise AssertionError(name)

try:
    with httpx.Client(base_url='http://127.0.0.1:8000',timeout=30,trust_env=False) as client:
        response=client.post('/api/auth/login',json={'username':'analyst','password':'demo-analyst-change-me'})
        response.raise_for_status()
        client.headers['X-CSRF-Token']=response.json()['csrf_token']
        pid=(ROOT/'.ecdat/demo-project-id.txt').read_text().strip()
        report['project_id']=pid
        workspace=client.get(f'/api/projects/{pid}/workspace').json()
        verification=next(row for row in reversed(workspace['verifications']) if row['status']=='passed')
        entry={'source':'Retained actual TLS acceptance observation','scope':'Registered authored laboratory','verification_id':verification['id'],'max_latency_ms':5000}
        for hsm in (False,True):
            response=client.post(f'/api/projects/{pid}/assess',json={'capabilities':{'key_exchange':{**entry,'requires_hsm':hsm}}})
            response.raise_for_status()
            assessment=response.json()
            workspace=client.get(f'/api/projects/{pid}/workspace').json()
            candidate=next(row for row in workspace['candidates'] if row.get('assessment_id')==assessment['id'] and row['role']=='key_exchange')
            check('assessment_links_candidate_'+str(hsm),candidate['id'] in assessment['candidate_ids'])
            check('measured_scope_preserved_'+str(hsm),candidate['provenance']['scope']=='Registered authored loopback TLS laboratory' and candidate['provenance']['verification_id']==verification['id'])
            if hsm:
                check('unknown_hsm_blocks',bool(candidate['candidates']) and all(row['status']=='blocked' and 'hsm_support_unknown' in row['unknowns'] for row in candidate['candidates']))
                report['hsm_blocked']=candidate
            else:
                check('measured_hybrid_feasible',any(row['algorithm']=='X25519MLKEM768' and row['status']=='feasible' for row in candidate['candidates']))
                report['measured']=candidate
        report['status']='passed'
except Exception as exc:
    report['status']='failed'
    report['error']=str(exc)
    raise
finally:
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'status':report['status'],'checks':len(report['checks']),'report':str(output)}))
