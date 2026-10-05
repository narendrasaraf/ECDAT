import base64
import copy
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('offline_replay', Path(__file__).resolve().parents[1] / 'scripts/replay.py')
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)

@pytest.fixture
def bundle(tmp_path):
    from ecdat.discovery.scanner import scan_directory
    from ecdat.exporting import cbom
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'app.py').write_text('import hashlib\nx = hashlib.sha256(b"hello")\n')
    scan = scan_directory(source, enable_syft=False)
    evidence = [{**item, 'artifact_id':'a', 'scan_id':'s'} for item in scan['evidence']]
    findings = [{**item, 'artifact_id':'a', 'scan_id':'s'} for item in scan['findings']]
    value = {'schema':'ecdat.bundle.v1', 'manifest':[{'artifact_id':'a','manifest':scan['manifest'],'manifest_digest':replay.digest(scan['manifest'])}],
        'snapshots':[{'artifact_id':'a','manifest_digest':replay.digest(scan['manifest']),'files':[{**item,'availability':'included','encoding':'base64','content':base64.b64encode((source/item['path']).read_bytes()).decode()} for item in scan['manifest']]}],
        'findings':findings,'evidence':evidence,'coverage':[{**item,'artifact_id':'a','scan_id':'s'} for item in scan['coverage']],
        'scans':[{'id':'s','artifact_id':'a',**scan}], 'proposals':[], 'decisions':[], 'verifications':[],
        'audit':[], 'audit_checkpoint':{'count':0,'head':'0'*64}, 'cbom':cbom(findings)}
    return value

def run(tmp_path, value, trusted=None):
    value = copy.deepcopy(value)
    value['content_digest'] = replay.digest(value)
    path = tmp_path/'bundle.json'
    path.write_text(json.dumps(value))
    return replay.replay(path, trusted)

def test_clean_actual_scanner_reproduces(tmp_path,bundle):
    result=run(tmp_path,bundle,replay.digest(bundle))
    assert result['status']=='static_reproduced'
    assert result['authenticated']
    assert any(c['check']=='static_replay' and c['citations_valid'] for c in result['checks'])

@pytest.mark.parametrize('kind', ['findings','evidence','coverage','citation'])
def test_resealed_semantic_changes_fail(tmp_path,bundle,kind):
    if kind=='citation':bundle['findings'][0]['evidence_ids']=['another-scan:evidence']
    elif kind=='findings':bundle[kind][0]['algorithm']='RSA'
    elif kind=='evidence':bundle[kind][0]['excerpt']='invented source evidence'
    else:bundle[kind][0]['status']='failed'
    assert run(tmp_path,bundle)['status']=='failed'

def test_missing_bytes_and_external_adapters_never_claim_complete(tmp_path,bundle):
    bundle['snapshots'][0]['files'][0]['availability']='withheld'
    assert run(tmp_path,bundle)['status']=='partial'

@pytest.mark.parametrize('path',['../escape','a/../b','C:/file','a\\b','CON.txt','/absolute','x:stream'])
def test_unsafe_paths(path):
    with pytest.raises(ValueError): replay.safe_path(path)

def test_trusted_checkpoint_rejects_resealed_truncation(tmp_path,bundle):
    expected=replay.digest(bundle)
    bundle['coverage']=[]
    assert run(tmp_path,bundle,expected)['status']=='failed'

def test_baseline_provenance(tmp_path,bundle):
    binding={'baseline_scan_id':'s','baseline_digest':replay.digest({k:bundle['scans'][0][k] for k in replay.SCAN_FIELDS}),'manifest_digest':bundle['manifest'][0]['manifest_digest']}
    bundle['proposals']=[{'id':'p','artifact_id':'a','author_id':'analyst','binding':binding,'proposal_digest':replay.digest(binding)}]
    assert run(tmp_path,bundle)['status']=='static_reproduced'
    bundle['scans'][0]['findings']=[]
    assert run(tmp_path,bundle)['status']=='failed'

def test_export_refuses_silent_truncation(monkeypatch):
    from ecdat import exporting
    monkeypatch.setattr(exporting,'rows',lambda *args,**kw:[{}]*10001)
    with pytest.raises(ValueError,match='incomplete evidence'):exporting.export_rows(None,'p','evidence')

def tls_observation(fallback=False):
    return {'hybrid':[{'connected':True,'group':'X25519MLKEM768','authorized':True,'payload_ok':True,'authentication':'RSA','protocol':'TLSv1.3'} for _ in range(8)],
            'classical':{'connected':True,'group':'X25519','authorized':True,'payload_ok':True} if fallback else {'connected':False,'error':'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE'}}

@pytest.mark.parametrize('fallback',[False,True])
def test_tls_fresh_behavior_comparison(monkeypatch,fallback):
    config={'tls':{'groups':['X25519MLKEM768','X25519'] if fallback else ['X25519MLKEM768']}}
    binding={'recipe':'tls-hybrid','recipe_version':'1','fallback':fallback,'after_digest':replay.digest(config)}
    proposal={'id':'p','binding':binding,'after':config}
    value={'decisions':[{'id':'d','proposal_id':'p','action':'approve'}], 'verifications':[{'id':'v','proposal_id':'p','decision_id':'d','observation':tls_observation(fallback)}]}
    monkeypatch.setattr(replay,'fresh_tls',lambda cfg:tls_observation(fallback))
    checks=[]
    replay.replay_tls(value,{'p':proposal},lambda check,status,**details:checks.append({'check':check,'status':status,**details}))
    assert checks[0]['status']=='passed'
    assert 'NOT reproduced' in checks[0]['identity']
    proposal['after']['tls']['groups']=['attacker.example']
    with pytest.raises(ValueError,match='bound recipe'):replay.replay_tls(value,{'p':proposal},lambda *a,**k:None)

def test_tls_transport_failure_is_not_strict_success():
    observation=tls_observation()
    observation['classical']['error']='ECONNREFUSED'
    assert not replay.tls_outcomes(observation,False)['peer_policy']
    observation=tls_observation()
    observation['hybrid'][0]['authorized']=False
    assert not replay.tls_outcomes(observation,False)['authenticated_payload']

@pytest.mark.parametrize('tamper',[False,True])
def test_isolated_replay_compares_external_evidence(tmp_path,bundle,monkeypatch,tamper):
    fresh=copy.deepcopy(bundle['scans'][0])
    coverage={'path':'.','adapter':'syft_inventory','status':'complete','version':'syft-test','sha256':None}
    evidence={'id':'syft-e','path':'package.json','line':None,'excerpt':'package observation','kind':'package','source':'syft','package':{'name':'demo','version':'1'}}
    fresh['coverage'].append(coverage)
    fresh['evidence'].append(evidence)
    bundle['coverage'].append({**coverage,'artifact_id':'a','scan_id':'s'})
    bundle['evidence'].append({**evidence,'artifact_id':'a','scan_id':'s'})
    if tamper:bundle['evidence'][-1]['excerpt']='invented external evidence'
    called=[]
    def scan(directory,isolated=False):
        called.append(isolated)
        return fresh
    monkeypatch.setattr(replay,'scan_restored',scan)
    bundle['content_digest']=replay.digest(bundle)
    path=tmp_path/'isolated.json'
    path.write_text(json.dumps(bundle))
    result=replay.replay(path,isolated=True)
    assert result['status']==('failed' if tamper else 'static_reproduced')
    assert called==[True]
