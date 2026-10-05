"""Capability provenance must not expand local evidence into global support."""
import pytest
from fastapi.testclient import TestClient
from ecdat.main import app
from ecdat.store import DB, put


@pytest.fixture(scope='module')
def case():
    with TestClient(app,client=('assessment-tests',50000)) as client:
        login=client.post('/api/auth/login',json={'username':'analyst','password':'demo-analyst-change-me'})
        assert login.status_code==200,login.text
        client.headers['X-CSRF-Token']=login.json()['csrf_token']
        project=client.post('/api/projects',json={'name':'Capability boundary tests','description':'Authored endpoint tests'})
        assert project.status_code==201,project.text
        yield client,project.json()['id']


def assess(case,capabilities=None):
    client,pid=case
    response=client.post(f'/api/projects/{pid}/assess',json={} if capabilities is None else {'capabilities':capabilities})
    assert response.status_code==200,response.text
    result=response.json()
    workspace=client.get(f'/api/projects/{pid}/workspace').json()
    options={row['role']:row for row in workspace['candidates'] if row.get('assessment_id')==result['id']}
    assert set(result['candidate_ids'])=={row['id'] for row in options.values()}
    return options


def test_explicit_attribution_can_establish_scoped_feasibility_and_hard_blocks(case):
    unknown=assess(case)['key_exchange']
    assert unknown['candidates'][0]['status']=='blocked'
    assert unknown['provenance']['kind']=='not_supplied'
    entry={'source':'Authored runtime/peer inventory, owner Alice','scope':'staging peer only','peer_capabilities':['X25519MLKEM768'],'runtime_capabilities':['X25519MLKEM768'],'protocol':'TLSv1.3'}
    feasible=assess(case,{'key_exchange':entry})['key_exchange']
    assert feasible['candidates'][0]['status']=='feasible'
    assert feasible['provenance']['scope']=='staging peer only'
    assert feasible['provenance']['kind']=='attributed_user_statement'
    assert all('wrong_crypto_role' in row['reasons'] for row in feasible['excluded'])
    blocked=assess(case,{'key_exchange':{**entry,'requires_hsm':True}})['key_exchange']
    assert 'hsm_support_unknown' in blocked['candidates'][0]['unknowns']
    rejected=assess(case,{'key_exchange':{**entry,'peer_capabilities':['X25519']}})['key_exchange']
    assert not rejected['candidates']
    assert any('unsupported_peer' in row['reasons'] for row in rejected['excluded'])
    # Unmeasured performance must remain unknown, even with positive support.
    limited=assess(case,{'key_exchange':{**entry,'max_memory_mb':512,'max_latency_ms':100}})['key_exchange']
    assert limited['candidates'][0]['status']=='blocked'
    assert {'measured_memory_mb_unknown','measured_latency_ms_unknown'}<=set(limited['candidates'][0]['unknowns'])


def test_measured_tls_scope_cannot_be_widened_or_used_as_signature_support(case):
    client,pid=case
    # Seed an explicitly authored unit fixture; live TLS is established separately
    # by acceptance_demo.py, not by this endpoint-contract test.
    with DB() as db:
        passed=put(db,pid,'verifications',{'status':'passed','candidate_id':'authored-test-candidate','observation':{'target':'lab-tls-01','hybrid':[{'connected':True,'authorized':True,'payload_ok':True,'protocol':'TLSv1.3','group':'X25519MLKEM768','elapsed_ms':25}]}})
        failed=put(db,pid,'verifications',{'status':'failed','observation':{}})
        db.commit()
    entry={'source':'Authored endpoint fixture','scope':'All enterprise peers','verification_id':passed['id'],'max_latency_ms':30}
    measured=assess(case,{'key_exchange':entry})['key_exchange']
    assert measured['candidates'][0]['status']=='feasible'
    assert measured['provenance']['scope']=='Registered authored loopback TLS laboratory'
    assert measured['provenance']['requested_scope']=='All enterprise peers'
    assert measured['provenance']['candidate_id']=='authored-test-candidate'
    slow=assess(case,{'key_exchange':{**entry,'max_latency_ms':20}})['key_exchange']
    assert any('max_latency_ms_exceeded' in row['reasons'] for row in slow['excluded'])
    for role,value in [('signature',entry),('key_exchange',{**entry,'verification_id':failed['id']}),('key_exchange',{**entry,'runtime_capabilities':['X25519MLKEM768']})]:
        response=client.post(f'/api/projects/{pid}/assess',json={'capabilities':{role:value}})
        assert response.status_code==422,response.text
    foreign=client.post('/api/projects',json={'name':'Other owned project'}).json()['id']
    assert client.post(f'/api/projects/{foreign}/assess',json={'capabilities':{'key_exchange':entry}}).status_code==404


def test_capability_input_requires_attribution_bounded_known_fields(case):
    client,pid=case
    entries=[{'source':' ','scope':'lab'},{'source':'author','scope':' '},{'source':'author','scope':'lab','runtime_capabilities':['x']*33},{'source':'author','scope':'lab','max_memory_mb':-1},{'source':'author','scope':'lab','requires_hsm':'false'},{'source':'author','scope':'lab','measured_latency_ms':1}]
    for entry in entries:
        response=client.post(f'/api/projects/{pid}/assess',json={'capabilities':{'key_exchange':entry}})
        assert response.status_code==422,response.text
