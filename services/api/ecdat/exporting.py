import base64
import hashlib
import json
import subprocess
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from .config import ROOT, STATE, NODE
from .store import rows, canonical, digest, audit_rows, uid, now
from .artifacts import snapshot_files

def cbom(findings):
    components=[]
    for item in findings:
        algorithm=item.get('algorithm','unknown')
        role=item.get('role','unknown')
        primitive={'key_exchange':'key-agree','kem':'kem','authentication':'signature','signature':'signature','hash':'hash','encryption':'ae'}.get(role,'other')
        components.append({'type':'cryptographic-asset','bom-ref':item['id'],'name':algorithm,'cryptoProperties':{'assetType':'algorithm','algorithmProperties':{'primitive':primitive}},'properties':[{'name':'ecdat:role','value':role},{'name':'ecdat:evidence-type','value':str(item.get('evidence_type',item.get('confidence','unknown')))},{'name':'ecdat:path','value':str(item.get('path',''))}]})
    return {'bomFormat':'CycloneDX','specVersion':'1.6','serialNumber':'urn:uuid:'+uid(),'version':1,'metadata':{'timestamp':now()},'components':components}

def validate_cbom(bom):
    schema_dir=ROOT/'schemas'
    schema=json.loads((schema_dir/'bom-1.6.schema.json').read_text(encoding='utf-8'))
    registry=Registry()
    for path in schema_dir.glob('*.json'):
        contents=json.loads(path.read_text(encoding='utf-8'))
        resource=Resource.from_contents(contents)
        registry=registry.with_resource(f'http://cyclonedx.org/schema/{path.name}',resource)
    Draft7Validator(schema,registry=registry).validate(bom)
    return {'status':'passed','schema':'CycloneDX 1.6 official JSON schema','schema_sha256':hashlib.sha256((schema_dir/'bom-1.6.schema.json').read_bytes()).hexdigest()}

def export_rows(db, project_id, kind):
    records = rows(db, project_id, kind, limit=10001)
    if len(records) > 10000:
        raise ValueError("Export exceeds record budget; refusing incomplete evidence")
    return records

def make_bundle(db,project):
    findings=export_rows(db,project.id,'findings')
    bom=cbom(findings)
    validation=validate_cbom(bom)
    artifacts=export_rows(db,project.id,'artifacts')
    snapshots=[{'artifact_id':a['id'],'manifest_digest':a['manifest_digest'],'files':snapshot_files(a)} for a in artifacts]
    envelope={'schema':'ecdat.bundle.v1','project_id':project.id,'created_at':now(),'manifest':[{ 'artifact_id':a['id'],'manifest':a['manifest'],'manifest_digest':a['manifest_digest']} for a in artifacts],'snapshots':snapshots,'scans':export_rows(db,project.id,'scans'),'findings':findings,'evidence':export_rows(db,project.id,'evidence'),'coverage':export_rows(db,project.id,'coverage'),'conflicts':export_rows(db,project.id,'conflicts'),'proposals':export_rows(db,project.id,'proposals'),'decisions':export_rows(db,project.id,'decisions'),'verifications':export_rows(db,project.id,'verifications'),'audit':audit_rows(db,project.id),'audit_checkpoint':{'count':project.audit_seq,'head':project.audit_head},'cbom':bom,'cbom_validation':validation,'versions':{'application':'0.1.0','canonicalization':'RFC8785','recipe':'tls-hybrid.v1'},'replay':{'supported':['manifest-bytes','audit-chain','proposal-binding','static-discovery','baseline-provenance'],'requires':['Python requirements.lock'],'limitation':'Offline replay compares static observations per scan. Original authenticated TLS and isolated Syft require separate runtime verification; private keys are not exported.'}}
    envelope['content_digest']=digest(envelope)
    export_id=uid()
    folder=STATE/'exports'/export_id
    folder.mkdir(parents=True)
    data=canonical(envelope)
    (folder/'bundle.json').write_bytes(data)
    (folder/'cbom.json').write_bytes(canonical(bom))
    return {'id':export_id,'status':'created','content_digest':envelope['content_digest'],'raw_sha256':hashlib.sha256(data).hexdigest(),'audit_checkpoint':envelope['audit_checkpoint'],'cbom_validation':validation,'download_url':f'/api/exports/{export_id}/download','cbom_url':f'/api/exports/{export_id}/cbom','size':len(data),'created_at':now()}

def seal_bundle(export_id):
    bundle=STATE/'exports'/export_id/'bundle.json'
    result=subprocess.run([NODE,str(ROOT/'packages/chain/scripts/api-anchor.mjs'),str(bundle),str(STATE/'chain')],cwd=ROOT,capture_output=True,text=True,timeout=110)
    if result.returncode:
        try:return json.loads(result.stdout)
        except ValueError:return {'status':'unavailable','reason':'Passport signing or local chain unavailable','details':result.stderr[-500:]}
    try:
        passport=json.loads(result.stdout)
        passport.pop('trust_path',None);passport.pop('passport_path',None)
        (bundle.parent/'passport.json').write_bytes(canonical(passport))
        return passport
    except ValueError:return {'status':'failed','reason':'Passport tool returned invalid JSON'}
