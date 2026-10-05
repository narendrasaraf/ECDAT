import hashlib
import asyncio
import json
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

import psutil
from argon2.exceptions import VerificationError
from fastapi import FastAPI, Request, Depends, UploadFile, File, HTTPException, Body
from fastapi.responses import JSONResponse, FileResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from . import config, ai
from .store import DB, Base, User, Member, Project, Record, Job, SessionToken, initialize, rows, put, uid, now, digest, audit, audit_rows, record_dict, job_dict
from .security import identity, require_role, project_access, record_access, error, throttle, hasher
from .artifacts import create_demo_artifact, artifact_path, finalize, manifest
from .governance import propose, assert_fresh, tls_observation
from .jobs import enqueue, worker_loop, stop_event
from .exporting import make_bundle, seal_bundle

class Payload(BaseModel):
    model_config=ConfigDict(extra='forbid')
class Login(Payload):
    username:str=Field(min_length=1,max_length=80)
    password:str=Field(min_length=1,max_length=200)
class Scan(Payload):
    artifact_id:str
class NewProject(Payload):
    name:str=Field(min_length=1,max_length=120)
    description:str=Field(default='',max_length=1500)
class Context(Payload):
    data_lifetime:list[float]|None=None
    migration_time:list[float]|None=None
    quantum_horizon:list[float]|None=None
    source:str=Field(default='User-entered scenario assumptions',max_length=500)
class Question(Payload):
    question:str=Field(min_length=1,max_length=1200)
class Proposal(Payload):
    artifact_id:str
    recipe:str='tls-hybrid'
    fallback:bool=False
class Decision(Payload):
    action:str
    reason:str=Field(min_length=1,max_length=1000)
class Plan(Payload):
    tasks:list[dict]=Field(max_length=200)
class InvestigationCheck(Payload):
    check_id:str

CapabilityName=Annotated[str,StringConstraints(strip_whitespace=True,min_length=1,max_length=100)]
CryptoRole=Literal['key_exchange','kem','signature','authentication','encryption','hash']
class CapabilityContext(Payload):
    source:Annotated[str,StringConstraints(strip_whitespace=True,min_length=1,max_length=500)]
    scope:Annotated[str,StringConstraints(strip_whitespace=True,min_length=1,max_length=300)]
    peer_capabilities:list[CapabilityName]|None=Field(default=None,max_length=32)
    runtime_capabilities:list[CapabilityName]|None=Field(default=None,max_length=32)
    protocol:CapabilityName|None=None
    requires_hsm:bool=Field(default=False,strict=True)
    hsm_capabilities:list[CapabilityName]|None=Field(default=None,max_length=32)
    max_memory_mb:float|None=Field(default=None,gt=0,le=1048576,allow_inf_nan=False)
    max_latency_ms:float|None=Field(default=None,gt=0,le=3600000,allow_inf_nan=False)
    verification_id:CapabilityName|None=None
class AssessmentRequest(Payload):
    capabilities:dict[CryptoRole,CapabilityContext]=Field(default_factory=dict,max_length=6)

def demo_users():
    if not config.DEMO:return
    with DB() as db:
        for name,role in [('analyst','analyst'),('reviewer','reviewer')]:
            if not db.scalar(select(User).where(User.username==name)):
                db.add(User(username=name,password=hasher.hash('demo-'+name+'-change-me'),role=role))
        db.commit()

@asynccontextmanager
async def lifespan(app):
    initialize();demo_users();stop_event.clear()
    worker=None
    if config.WORKER:
        worker=threading.Thread(target=worker_loop,daemon=True,name='ecdat-one-worker');worker.start()
    yield
    stop_event.set()
    if worker:worker.join(timeout=5)

app=FastAPI(title='ECDAT Evidence Workbench',version='0.1.0',lifespan=lifespan)
body_slots=threading.BoundedSemaphore(2)

@app.middleware('http')
async def request_boundary(request:Request,call_next):
    request_id=uid()
    request.state.request_id=request_id
    length=request.headers.get('content-length','0')
    if not length.isdigit() or int(length)>32*1024*1024:
        return JSONResponse({'error':{'code':'request_too_large','message':'Maximum request size is 32 MB','request_id':request_id}},status_code=413)
    if request.method not in ('GET','HEAD','OPTIONS'):
        chunks=[]
        received=0
        try:
            async with asyncio.timeout(30):
                async for chunk in request.stream():
                    received+=len(chunk)
                    if received>32*1024*1024:
                        return JSONResponse({'error':{'code':'request_too_large','message':'Maximum request size is 32 MB','request_id':request_id}},status_code=413)
                    chunks.append(chunk)
                request._body=b''.join(chunks)
        except TimeoutError:
            return JSONResponse({'error':{'code':'intake_timeout','message':'Request body exceeded the 30 second intake window','request_id':request_id}},status_code=408)
        origin=request.headers.get('origin')
        if origin:
            allowed={'http://127.0.0.1:8000','http://localhost:8000','http://localhost:5173','http://127.0.0.1:5173'}
            env_origin=os.getenv('ECDAT_ORIGIN')
            if env_origin:
                for item in env_origin.split(','):
                    if item.strip():allowed.add(item.strip().rstrip('/'))
            if origin.rstrip('/') not in allowed:
                return JSONResponse({'error':{'code':'origin_forbidden','message':'Request origin is not permitted','request_id':request_id}},status_code=403)
        if request.headers.get('content-type','').split(';')[0]=='application/json':
            raw=await request.body()
            def unique(pairs):
                result={}
                for key,value in pairs:
                    if key in result:raise ValueError('Duplicate JSON property')
                    result[key]=value
                return result
            try:json.loads(raw,object_pairs_hook=unique,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('Nonfinite JSON')))
            except ValueError:
                return JSONResponse({'error':{'code':'invalid_json','message':'JSON must have unique properties and finite values','request_id':request_id}},status_code=422)
    response=await call_next(request)
    response.headers.update({'X-Request-ID':request_id,'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'"})
    return response

@app.middleware('http')
async def bounded_mutations(request:Request,call_next):
    if request.method in ('GET','HEAD','OPTIONS'):return await call_next(request)
    if not body_slots.acquire(blocking=False):
        return JSONResponse({'error':{'code':'intake_busy','message':'Two input requests are active. Retry shortly.','request_id':uid()}},status_code=429)
    try:return await call_next(request)
    finally:body_slots.release()

@app.exception_handler(HTTPException)
async def http_error(request,exc):
    detail=exc.detail if isinstance(exc.detail,dict) else {'code':'request_failed','message':str(exc.detail)}
    return JSONResponse({'error':{**detail,'request_id':getattr(request.state,'request_id',None)}},status_code=exc.status_code)

@app.exception_handler(RequestValidationError)
async def validation_error(request,exc):
    return JSONResponse({'error':{'code':'invalid_input','message':'Input does not match the API contract','details':[{'location':list(e['loc']),'message':e['msg']} for e in exc.errors()],'request_id':request.state.request_id}},status_code=422)

@app.exception_handler(ValueError)
async def domain_error(request,exc):
    return JSONResponse({'error':{'code':'domain_validation','message':str(exc),'request_id':request.state.request_id}},status_code=422)

@app.exception_handler(IntegrityError)
async def integrity_error(request,exc):
    return JSONResponse({'error':{'code':'conflict','message':'This action conflicts with a record already persisted. Refresh and retry.','request_id':request.state.request_id}},status_code=409)

@app.get('/api/health')
def health():
    return {'status':'ok','profile':config.PROFILE,'version':'0.1.0','demo_enabled':config.DEMO,'capabilities':{'isolation':config.PROFILE=='isolated','ai':ai.capabilities(),'blockchain':{'status':'not_checked','network':'local development EVM unless explicitly configured'},'node':{'configured':Path(config.NODE).exists()}},'memory':{'available_mb':psutil.virtual_memory().available//1024**2,'admission_floor_mb':config.MEMORY_RESERVE_MB}}

@app.post('/api/auth/login')
def login(payload:Login,request:Request):
    throttle(request.client.host if request.client else 'local')
    with DB() as db:
        user=db.scalar(select(User).where(User.username==payload.username))
        try:
            # A fixed invalid hash still incurs a password-KDF cost for unknown users.
            valid=hasher.verify(user.password if user else hasher.hash('not-a-password'),payload.password)
        except VerificationError:valid=False
        if not user or not valid:error(401,'invalid_credentials','Username or password is incorrect.')
        token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(24)
        db.add(SessionToken(token_hash=hashlib.sha256(token.encode()).hexdigest(),user_id=user.id,csrf=csrf,expires=time.time()+8*3600));db.commit()
        response=JSONResponse({'user':{'id':user.id,'username':user.username,'role':user.role},'csrf_token':csrf})
        response.set_cookie('ecdat_session',token,httponly=True,secure=config.COOKIE_SECURE,samesite='strict',max_age=8*3600,path='/')
        return response

@app.get('/api/auth/me')
def me(user=Depends(identity)):
    return {'user':{k:v for k,v in user.items() if k!='csrf_token'},'csrf_token':user['csrf_token']}

@app.post('/api/auth/logout')
def logout(request:Request,user=Depends(identity)):
    with DB() as db:
        token=db.get(SessionToken,hashlib.sha256(request.cookies['ecdat_session'].encode()).hexdigest());db.delete(token);db.commit()
    response=JSONResponse({'status':'signed_out'});response.delete_cookie('ecdat_session');return response

@app.get('/api/projects')
def projects(user=Depends(identity)):
    with DB() as db:
        return [{'id':p.id,'name':p.name,'description':p.description,'disclosure':p.disclosure} for p in db.scalars(select(Project).join(Member).where(Member.user_id==user['id']))]

@app.post('/api/projects/demo')
def demo(fresh:bool=False,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    if not config.DEMO:error(403,'demo_disabled','Explicit demo setup is required.')
    with DB() as db:
        existing=db.scalar(select(Project).join(Member).where(Member.user_id==user['id'],Project.disclosure=='public-demo'))
        if existing and not fresh:return {'id':existing.id,'name':existing.name,'description':existing.description}
        p=Project(name='Payment gateway · migration case',description='Authored laboratory. Trace a cryptographic claim from evidence through approved change and independent receipt.',disclosure='public-demo')
        db.add(p);db.flush()
        for account in db.scalars(select(User).where(User.username.in_(['analyst','reviewer']))):db.add(Member(project_id=p.id,user_id=account.id))
        artifact=put(db,p.id,'artifacts',create_demo_artifact())
        knowledge=json.loads((config.ROOT/'knowledge/registry.json').read_text(encoding='utf-8'))
        for source in knowledge['sources']:
            put(db,p.id,'evidence',{'kind':'curated_knowledge','source':source['url'],'source_id':source['id'],'title':source['title'],'authority':source['authority'],'role':source['role'],'excerpt':source['excerpt'],'reviewed_at':source['reviewed_at']})
        put(db,p.id,'context',{'data_lifetime':[8,12],'migration_time':[2,4],'quantum_horizon':[8,15],'source':'Authored scenario assumptions; not a quantum computer forecast','author_id':user['id']})
        from .analysis import plan_tasks
        tasks=[{'id':'runtime','title':'Shared hybrid TLS runtime','owner':'Platform team','depends_on':[],'status':'unknown','reason':'Verify the actual runtime and peer capabilities'},{'id':'payments','title':'Payment service migration','owner':'Payments','depends_on':['runtime'],'status':'pending'},{'id':'gateway','title':'Gateway migration','owner':'Gateway','depends_on':['runtime'],'status':'pending'},{'id':'hsm','title':'Signing HSM supplier evidence','owner':'Signing supplier','depends_on':[],'status':'blocked','reason':'No compatible ML-DSA HSM attestation has been supplied'}]
        put(db,p.id,'plan',plan_tasks(tasks))
        audit(db,p.id,user['id'],'demo.created',{'artifact_id':artifact['id'],'provenance':'authored fixtures'})
        job=enqueue(db,p.id,'scan',{'artifact_id':artifact['id']},'demo-initial-scan',user['id'])
        db.commit()
        return {'id':p.id,'name':p.name,'description':p.description,'artifact_id':artifact['id'],'job_id':job.id}

@app.post('/api/projects',status_code=201)
def new_project(payload:NewProject,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    with DB() as db:
        project=Project(name=payload.name,description=payload.description,disclosure='restricted');db.add(project);db.flush()
        db.add(Member(project_id=project.id,user_id=user['id']));db.flush()
        audit(db,project.id,user['id'],'project.created',{'disclosure':'restricted'});db.commit()
        return {'id':project.id,'name':project.name,'description':project.description,'disclosure':project.disclosure}

@app.get('/api/projects/{project_id}/workspace')
def workspace(project_id:str,user=Depends(identity)):
    with DB() as db:
        p=project_access(db,project_id,user)
        kinds=['artifacts','findings','evidence','coverage','conflicts','context','assessments','candidates','plan','advice','investigations','proposals','decisions','verifications','exports','passports']
        result={kind:rows(db,project_id,kind,limit=500) for kind in kinds}
        result['advice']=[ai.current_policy_view(r) for r in result['advice']]
        result['investigations']=[ai.current_policy_view(r) for r in result['investigations']]
        # Storage paths are internal; the manifest is the public artifact identity.
        for artifact in result['artifacts']:artifact.pop('storage_id',None)
        result.update(project={'id':p.id,'name':p.name,'description':p.description,'disclosure':p.disclosure},jobs=[job_dict(j) for j in db.scalars(select(Job).where(Job.project_id==project_id).order_by(Job.created_at).limit(100))],audit=audit_rows(db,project_id)[-100:],pagination={'limit_per_collection':500,'more_available_via':'/api/projects/{id}/records/{kind}'})
        return result

@app.get('/api/projects/{project_id}/records/{kind}')
def collection(project_id:str,kind:str,offset:int=0,limit:int=50,user=Depends(identity)):
    if kind not in {'artifacts','findings','evidence','coverage','conflicts','proposals','decisions','verifications','investigations','passports'}:error(404,'not_found','Collection not found')
    if offset<0 or not 1<=limit<=100:error(422,'invalid_page','Page must contain 1–100 records')
    with DB() as db:
        project_access(db,project_id,user)
        return [record_dict(r) for r in db.scalars(select(Record).where(Record.project_id==project_id,Record.kind==kind).order_by(Record.created_at,Record.id).offset(offset).limit(limit))]

@app.post('/api/projects/{project_id}/artifacts',status_code=201)
async def upload(project_id:str,file:UploadFile=File(...),user=Depends(identity)):
    require_role(user,'analyst','administrator')
    with DB() as db:project_access(db,project_id,user)
    if config.PROFILE!='isolated':error(409,'isolation_required','External uploads require the isolated scanner profile. The current profile permits authored fixtures only.')
    archive=config.STATE/'staging'/(uid()+'.zip');archive.parent.mkdir(exist_ok=True)
    size=0
    try:
        with archive.open('wb') as stream:
            while chunk:=await file.read(1024*1024):
                size+=len(chunk)
                if size>30*1024*1024:error(413,'upload_too_large','Archive exceeds 30 MB')
                stream.write(chunk)
        from .discovery import safe_extract_archive
        destination=config.STATE/'staging'/uid()
        extracted=safe_extract_archive(archive,destination)
        if not extracted.get('ok'):error(422,'archive_rejected',extracted.get('error','Unsafe archive'))
        data=finalize(destination,name=Path(file.filename or 'archive.zip').name)
        with DB() as db:
            item=put(db,project_id,'artifacts',data);audit(db,project_id,user['id'],'artifact.uploaded',{'artifact_id':item['id'],'manifest_digest':data['manifest_digest']});db.commit()
            item.pop('storage_id',None);return item
    finally:
        archive.unlink(missing_ok=True)

@app.post('/api/projects/{project_id}/scan',status_code=202)
def scan(project_id:str,payload:Scan,request:Request,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    with DB() as db:
        project_access(db,project_id,user)
        artifact=record_access(db,Record,payload.artifact_id,user,'artifacts')
        if artifact.project_id!=project_id:error(404,'not_found','Artifact not found')
        job=enqueue(db,project_id,'scan',payload.model_dump(),request.headers.get('Idempotency-Key',uid()),user['id']);db.commit();return job_dict(job)

@app.get('/api/jobs/{job_id}')
def get_job(job_id:str,user=Depends(identity)):
    with DB() as db:return job_dict(record_access(db,Job,job_id,user))

@app.post('/api/jobs/{job_id}/cancel')
def cancel(job_id:str,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    with DB() as db:
        job=record_access(db,Job,job_id,user)
        db.refresh(job,with_for_update=True)
        if job.status in ('queued','running'):
            job.status='cancelled';job.fence+=1;job.lease_until=0;job.message='Cancellation recorded; child process termination requested'
            audit(db,job.project_id,user['id'],'job.cancelled',{'job_id':job_id});db.commit()
        return job_dict(job)

@app.post('/api/jobs/{job_id}/retry',status_code=202)
def retry(job_id:str,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    with DB() as db:
        job=record_access(db,Job,job_id,user)
        db.refresh(job,with_for_update=True)
        if job.status not in ('failed','cancelled') or job.attempt>=3:error(409,'retry_forbidden','Only failed or cancelled jobs with remaining attempts can retry')
        job.status='queued';job.fence+=1;job.message='Retry queued';job.lease_until=0
        audit(db,job.project_id,user['id'],'job.retried',{'job_id':job_id});db.commit();return job_dict(job)

@app.post('/api/projects/{project_id}/context')
def context(project_id:str,payload:Context,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    from .analysis import assess_context
    assess_context(payload.data_lifetime,payload.migration_time,payload.quantum_horizon)
    with DB() as db:
        project_access(db,project_id,user)
        item=put(db,project_id,'context',{**payload.model_dump(),'author_id':user['id']});audit(db,project_id,user['id'],'context.revised',{'context_id':item['id']});db.commit();return item

@app.post('/api/projects/{project_id}/assess')
def assess(project_id:str,payload:AssessmentRequest|None=Body(default=None),user=Depends(identity)):
    require_role(user,'analyst','administrator')
    from .analysis import assess_context,candidate_options,REGISTRY
    with DB() as db:
        project_access(db,project_id,user)
        contexts=rows(db,project_id,'context');current=contexts[-1] if contexts else {}
        capability_contexts=(payload or AssessmentRequest()).capabilities
        assessment=put(db,project_id,'assessments',{**assess_context(current.get('data_lifetime'),current.get('migration_time'),current.get('quantum_horizon')),'context_id':current.get('id'),'author_id':user['id'],'capabilities':{role:entry.model_dump() for role,entry in capability_contexts.items()}})
        candidate_ids=[]
        for role in sorted(set(['key_exchange','signature','encryption'])|set(capability_contexts)):
            supplied=capability_contexts.get(role)
            constraints=supplied.model_dump(exclude={'source','scope','verification_id'}) if supplied else {}
            provenance={'kind':'not_supplied','scope':'Unspecified; compatibility remains unknown'}
            if supplied:
                provenance={'kind':'attributed_user_statement','source':supplied.source,'scope':supplied.scope,'author_id':user['id'],'limitations':['Capability statements are attributed inputs, not independently measured compatibility.']}
            if supplied and supplied.verification_id:
                verification=record_access(db,Record,supplied.verification_id,user,'verifications')
                if verification.project_id!=project_id:error(404,'not_found','Verification not found in this project')
                data=verification.data
                if role not in ('key_exchange','kem') or data.get('status')!='passed':
                    error(422,'invalid_capability_evidence','A passed TLS verification supports only its measured key-exchange role')
                if supplied.peer_capabilities is not None or supplied.runtime_capabilities is not None:
                    error(422,'capability_override','Measured runtime and peer support cannot be replaced by manual capability values')
                observation=data.get('observation',{})
                samples=observation.get('hybrid',[])
                groups=sorted({sample['group'] for sample in samples if sample.get('connected') is True and sample.get('authorized') is True and sample.get('payload_ok') is True and sample.get('protocol')=='TLSv1.3' and sample.get('group')=='X25519MLKEM768'})
                if not groups:error(422,'missing_capability_observation','Verification has no authenticated hybrid TLS observation')
                constraints.update(peer_capabilities=groups,runtime_capabilities=groups)
                if constraints['protocol'] is None:constraints['protocol']='TLSv1.3'
                registry=[dict(entry) for entry in REGISTRY]
                # Only the measured lab candidate gets latency evidence; no memory
                # or HSM support is inferred from a successful TLS handshake.
                latencies=[sample.get('elapsed_ms') for sample in samples]
                if latencies and all(isinstance(value,(int,float)) and not isinstance(value,bool) and 0<=value<3600000 for value in latencies):
                    for entry in registry:
                        if entry['id']=='tls-hybrid-mlkem768':entry['measured_latency_ms']=max(latencies)
                constraints['candidates']=registry
                provenance={'kind':'measured_registered_lab','source':supplied.source,'scope':'Registered authored loopback TLS laboratory','requested_scope':supplied.scope,'verification_id':verification.id,'candidate_id':data.get('candidate_id'),'observation_target':observation.get('target'),'observed_at':observation.get('observed_at'),'author_id':user['id'],'limitations':['Support applies only to the recorded laboratory candidate, runtime and peer.','RSA authentication remains; enterprise peers, HSM support and memory budgets are not established.','Latency limit uses the maximum observed handshake duration in this finite local sample.']}
            candidate=put(db,project_id,'candidates',{**candidate_options(role,**constraints),'assessment_id':assessment['id'],'context_id':current.get('id'),'provenance':provenance,'constraints':{key:value for key,value in constraints.items() if key!='candidates'},'feasibility_claim':'Passes supplied hard constraints within the attributed scope; migration still requires review and verification.'})
            candidate_ids.append(candidate['id'])
        assessment['candidate_ids']=candidate_ids
        db.get(Record,assessment['id']).data=assessment
        audit(db,project_id,user['id'],'assessment.created',{'assessment_id':assessment['id']});db.commit();return assessment

@app.post('/api/projects/{project_id}/plan')
def plan(project_id:str,payload:Plan,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    from .analysis import plan_tasks
    result=plan_tasks(payload.tasks)
    with DB() as db:
        project_access(db,project_id,user);item=put(db,project_id,'plan',result);audit(db,project_id,user['id'],'plan.revised',{'plan_id':item['id']});db.commit();return item

def request_advice(project_id,payload,user,kind):
    require_role(user,'analyst','administrator')
    with DB() as db:
        p=project_access(db,project_id,user);evidence=rows(db,project_id,'evidence',limit=200);disclosure=p.disclosure
        scoped_findings=rows(db,project_id,'findings',limit=1000)
        for item in evidence:
            item['claims']=[{'algorithm':f.get('algorithm'),'role':f.get('role'),'parameters':f.get('parameters'),'scope':f.get('claim',{}).get('scope')} for f in scoped_findings if item['id'] in f.get('evidence_ids',[])][:4]
    result=ai.generate(payload.question,evidence,disclosure,kind)
    with DB() as db:
        item=put(db,project_id,kind,result);audit(db,project_id,user['id'],'ai.'+result['status'],{'record_id':item['id'],'provider':result['provider'],'context_digest':result.get('context_digest')});db.commit();return item

@app.post('/api/projects/{project_id}/advice')
def advice(project_id:str,payload:Question,user=Depends(identity)):
    return request_advice(project_id,payload,user,'advice')

@app.post('/api/projects/{project_id}/investigations')
def investigate(project_id:str,payload:Question,user=Depends(identity)):
    return request_advice(project_id,payload,user,'investigations')

@app.post('/api/investigations/{investigation_id}/checks',status_code=202)
def investigation_check(investigation_id:str,payload:InvestigationCheck,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    with DB() as db:
        inv=record_access(db,Record,investigation_id,user,'investigations');pid=inv.project_id
        if ai.current_policy_view(inv.data).get('status')!='validated' or (inv.data.get('suggested_check') or {}).get('check_id')!=payload.check_id:error(409,'check_not_proposed','A current validated investigation must propose this registered check')
        artifacts=rows(db,pid,'artifacts')
        history=[r for r in rows(db,pid,'investigations') if r.get('parent_id')==investigation_id]
        if len(history)>=2:error(409,'investigation_limit','This investigation reached its check limit')
        if payload.check_id not in ai.CHECKS:error(403,'check_forbidden','Unknown check')
        job=enqueue(db,pid,'investigation',{'investigation_id':investigation_id,'check_id':payload.check_id},'investigation:'+investigation_id+':'+payload.check_id,user['id'])
        db.commit();return job_dict(job)

@app.post('/api/projects/{project_id}/proposals')
def proposal(project_id:str,payload:Proposal,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    if payload.recipe!='tls-hybrid':error(422,'recipe_unsupported','Choose a registered recipe')
    with DB() as db:
        project_access(db,project_id,user);artifact=record_access(db,Record,payload.artifact_id,user,'artifacts')
        if artifact.project_id!=project_id:error(404,'not_found','Artifact not found')
        scans=[s for s in rows(db,project_id,'scans') if s['artifact_id']==artifact.id]
        if not scans:error(409,'baseline_missing','Complete baseline discovery before creating a proposal')
        data=propose(artifact.data,artifact.id,user['id'],payload.fallback)
        data['binding']['baseline_scan_id']=scans[-1]['id']
        data['binding']['baseline_digest']=digest({k:scans[-1][k] for k in ('manifest','coverage','findings','evidence','conflicts')})
        data['proposal_digest']=digest(data['binding'])
        item=put(db,project_id,'proposals',data);audit(db,project_id,user['id'],'proposal.created',{'proposal_id':item['id'],'digest':data['proposal_digest']});db.commit();return item

@app.post('/api/proposals/{proposal_id}/decisions')
def decide(proposal_id:str,payload:Decision,user=Depends(identity)):
    require_role(user,'reviewer','administrator')
    if payload.action not in ('approve','reject'):error(422,'invalid_action','Decision must approve or reject')
    with DB() as db:
        proposal=record_access(db,Record,proposal_id,user,'proposals')
        db.execute(select(Record).where(Record.id==proposal_id).with_for_update())
        if proposal.data['author_id']==user['id']:error(403,'self_approval','A different authenticated reviewer must decide this proposal')
        if any(d.get('proposal_id')==proposal_id for d in rows(db,proposal.project_id,'decisions')):error(409,'decision_final','A decision is already recorded for this exact proposal')
        artifact=db.get(Record,proposal.data['artifact_id'])
        if digest(manifest(artifact_path(artifact.data)))!=proposal.data['manifest_digest']:error(409,'stale_proposal','Input bytes changed; create a new proposal')
        item=put(db,proposal.project_id,'decisions',{'proposal_id':proposal_id,'proposal_digest':proposal.data['proposal_digest'],'reviewer_id':user['id'],'reviewer_name':user['username'],'action':payload.action,'reason':payload.reason},record_id='decision:'+proposal_id)
        audit(db,proposal.project_id,user['id'],'proposal.'+payload.action,{'decision_id':item['id'],'proposal_digest':proposal.data['proposal_digest']});db.commit();return item

@app.post('/api/proposals/{proposal_id}/execute',status_code=202)
def execute(proposal_id:str,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    with DB() as db:
        proposal=record_access(db,Record,proposal_id,user,'proposals')
        decision=db.get(Record,'decision:'+proposal_id)
        if not decision or decision.data['action']!='approve':error(409,'approval_required','An independent reviewer must approve the exact proposal first')
        artifact=db.get(Record,proposal.data['artifact_id']);assert_fresh(proposal.data,artifact.data,decision.data)
        job=enqueue(db,proposal.project_id,'execute',{'artifact_id':artifact.id,'proposal_id':proposal_id,'decision_id':decision.id},'execute:'+proposal_id,user['id']);db.commit();return job_dict(job)

@app.post('/api/projects/{project_id}/exports')
def export(project_id:str,user=Depends(identity)):
    with DB() as db:
        p=project_access(db,project_id,user)
        audit(db,project_id,user['id'],'export.requested',{})
        data=make_bundle(db,p);item=put(db,project_id,'exports',data,record_id=data['id']);db.commit();return item

@app.get('/api/exports/{export_id}/download')
def download(export_id:str,user=Depends(identity)):
    with DB() as db:record_access(db,Record,export_id,user,'exports')
    return FileResponse(config.STATE/'exports'/export_id/'bundle.json',media_type='application/json',filename='ecdat-evidence-bundle.json')

@app.get('/api/exports/{export_id}/cbom')
def download_cbom(export_id:str,user=Depends(identity)):
    with DB() as db:record_access(db,Record,export_id,user,'exports')
    return FileResponse(config.STATE/'exports'/export_id/'cbom.json',media_type='application/json',filename='ecdat-cbom.json')

@app.get('/api/exports/{export_id}/passport')
def download_passport(export_id:str,user=Depends(identity)):
    with DB() as db:record_access(db,Record,export_id,user,'exports')
    path=config.STATE/'exports'/export_id/'passport.json'
    if not path.exists():error(404,'passport_missing','Passport has not been created')
    return FileResponse(path,media_type='application/json',filename='ecdat-migration-passport.json')

@app.post('/api/exports/{export_id}/anchor',status_code=202)
def anchor(export_id:str,user=Depends(identity)):
    require_role(user,'analyst','administrator')
    with DB() as db:
        export=record_access(db,Record,export_id,user,'exports');pid=export.project_id
        job=enqueue(db,pid,'anchor',{'export_id':export_id},'anchor:'+export_id,user['id']);db.commit();return job_dict(job)

@app.get('/api/projects/{project_id}/graph')
def graph(project_id:str,finding_id:str|None=None,user=Depends(identity)):
    with DB() as db:
        project_access(db,project_id,user)
        findings=rows(db,project_id,'findings',limit=200)
        chosen=[f for f in findings if not finding_id or f['id']==finding_id][:15]
        evidence_ids={i for f in chosen for i in f.get('evidence_ids',[])}
        evidence=[e for e in rows(db,project_id,'evidence',limit=1000) if e['id'] in evidence_ids][:45]
        visible={e['id'] for e in evidence}
        return {'nodes':[{'id':f['id'],'kind':'finding','label':f.get('algorithm'),'role':f.get('role')} for f in chosen]+[{'id':e['id'],'kind':'evidence','label':e.get('path',e.get('kind'))} for e in evidence],'edges':[{'from':f['id'],'to':i,'relation':'supported_by'} for f in chosen for i in f.get('evidence_ids',[]) if i in visible],'limit':60}

@app.get('/{path:path}')
def web(path:str):
    if path.startswith('api/'):
        error(404,'not_found','Endpoint not found')
    root=(config.ROOT/'apps/web/dist').resolve()
    target=(root/path).resolve()
    if target.is_relative_to(root) and target.is_file():return FileResponse(target)
    if (root/'index.html').exists():return FileResponse(root/'index.html')
    return JSONResponse({'message':'ECDAT API is running. Build apps/web to serve the workbench.','docs':'/docs'})
