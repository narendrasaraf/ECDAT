"""Provider failures cannot obstruct deterministic review or gain project authority."""
import socket
from fastapi.testclient import TestClient
from ecdat import ai
from ecdat.main import app
from ecdat.store import DB, put

def test_closed_provider_keeps_core_operational(monkeypatch):
    # Reserve a non-listening loopback port: real connection refusal, no AI mock.
    with socket.socket() as unavailable:
        unavailable.bind(('127.0.0.1', 0))
        monkeypatch.setenv('OLLAMA_HOST', 'http://127.0.0.1:' + str(unavailable.getsockname()[1]))
        monkeypatch.setattr(ai, 'AI_PROVIDER', 'ollama')
        with TestClient(app) as client:
            login=client.post('/api/auth/login',json={'username':'analyst','password':'demo-analyst-change-me'})
            client.headers['X-CSRF-Token']=login.json()['csrf_token']
            pid=client.post('/api/projects',json={'name':'Outage isolation'}).json()['id']
            with DB() as db:
                put(db,pid,'evidence',{'kind':'authored','excerpt':'Public test of provider outage'})
                db.commit()
            result=client.post(f'/api/projects/{pid}/advice',json={'question':'Explain the evidence'}).json()
            assert result['status']=='unavailable',result
            assert result['authority']=='hypothesis only'
            assert client.get('/api/health').status_code==200
            context=client.post(f'/api/projects/{pid}/context',json={'data_lifetime':[8,12],'migration_time':[2,4],'quantum_horizon':[8,15]})
            assert context.status_code==200,context.text
            assessment=client.post(f'/api/projects/{pid}/assess',json={})
            assert assessment.status_code==200 and assessment.json()['status']=='scenario_dependent'
            workspace=client.get(f'/api/projects/{pid}/workspace').json()
            assert workspace['findings']==[] and workspace['decisions']==[]
            assert workspace['advice'][-1]['status']=='unavailable'
            assert not ai._admission.locked()

def test_remote_provider_cannot_receive_restricted_evidence(monkeypatch):
    monkeypatch.setattr(ai,'AI_PROVIDER','groq')
    def forbidden(*args,**kwargs):
        raise AssertionError('Restricted evidence reached the network')
    monkeypatch.setattr(ai.httpx,'Client',forbidden)
    result=ai.generate('Explain this private record',[{'id':'private','excerpt':'Private material'}],'restricted')
    assert result['status']=='blocked'
