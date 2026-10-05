import json
import os
import subprocess
import sys
import threading
import time

import psutil
from sqlalchemy import select, update, or_

from .config import ROOT, PROFILE, MEMORY_RESERVE_MB
from .store import DB, Job, Record, Outbox, ResourceLease, audit, put, rows, record_dict, now, uid, digest, acquire_resource, release_resource
from .artifacts import artifact_path, manifest
from .governance import create_candidate, tls_observation, verify_migration

stop_event=threading.Event()

def enqueue(db, project_id, kind, payload, key, actor):
    existing=db.scalar(select(Job).where(Job.project_id==project_id,Job.idempotency_key==key))
    if existing:
        if existing.kind != kind or existing.payload != payload:
            raise ValueError("Idempotency key was already used for different work")
        return existing
    job=Job(project_id=project_id,kind=kind,payload=payload,idempotency_key=key)
    db.add(job);db.flush()
    db.add(Outbox(project_id=project_id,job_id=job.id,kind=kind))
    audit(db,project_id,actor,'job.queued',{'job_id':job.id,'kind':kind})
    return job

def claim(db):
    current=time.time()
    job=db.scalar(select(Job).where(or_(Job.status=='queued',(Job.status=='running') & (Job.lease_until<current))).order_by(Job.created_at).with_for_update(skip_locked=True).limit(1))
    if not job: return None
    if job.attempt>=3:
        job.status='failed';job.message='Worker lease expired too many times';db.commit();return None
    old_fence=job.fence
    updated=db.execute(update(Job).where(Job.id==job.id,Job.fence==old_fence,Job.status.in_(['queued','running'])).values(status='running',fence=old_fence+1,attempt=job.attempt+1,lease_until=current+180,message='Running bounded job'))
    if updated.rowcount!=1:
        db.rollback();return None
    db.execute(update(Outbox).where(Outbox.job_id==job.id).values(published=1))
    db.commit();db.refresh(job)
    return job.id,job.fence

def still_active(job_id,fence):
    with DB() as db:
        j=db.get(Job,job_id)
        return j and j.status=='running' and j.fence==fence and j.lease_until>time.time()

def renew_leases(job_id,fence,owner,finished):
    while not finished.wait(10):
        current=time.time()
        with DB() as db:
            resource=db.execute(update(ResourceLease).where(ResourceLease.name=='heavy',ResourceLease.owner==owner,ResourceLease.expires>current).values(expires=current+180))
            job=db.execute(update(Job).where(Job.id==job_id,Job.fence==fence,Job.status=='running',Job.lease_until>current).values(lease_until=current+180))
            if resource.rowcount!=1 or job.rowcount!=1:
                db.rollback()
                # A stale controller must not continue producing accepted effects.
                db.execute(update(Job).where(Job.id==job_id,Job.fence==fence,Job.status=='running').values(fence=fence+1,status='failed',lease_until=0,message='Worker lost its resource lease; retry required'))
                db.commit();return
            db.commit()

def run_scan(artifact, job_id, fence):
    path=artifact_path(artifact)
    if manifest(path)!=artifact['manifest']:
        raise ValueError('Immutable input manifest no longer matches stored bytes')
    if PROFILE=='isolated':
        command=['docker','run','--rm','--name','ecdat-scan-'+job_id,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--cpus','1','--pids-limit','96','--tmpfs','/tmp:rw,noexec,nosuid,size=128m','--user','65532:65532','--mount',f'type=bind,source={path},target=/input,readonly','ecdat-scanner:local']
        env={k:v for k,v in os.environ.items() if k in ('PATH','SYSTEMROOT','WINDIR','TEMP','TMP','USERPROFILE')}
    elif artifact.get('authored_fixture'):
        command=[sys.executable,'-m','ecdat.scan_runner',str(path)]
        env={k:v for k,v in os.environ.items() if k in ('PATH','SYSTEMROOT','WINDIR','TEMP','TMP')}
        env['PYTHONPATH']=str(ROOT/'services/api')
    else:
        raise ValueError('External artifacts require the isolated scanner profile')
    # Files prevent a parser from holding the API pipe open. Output has a hard cap.
    import tempfile
    with tempfile.TemporaryFile() as output,tempfile.TemporaryFile() as errors:
        process=subprocess.Popen(command,stdout=output,stderr=errors,env=env,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        start=time.monotonic()
        while process.poll() is None:
            if time.monotonic()-start>100 or output.tell()>8_000_000 or errors.tell()>1_000_000 or not still_active(job_id,fence) or stop_event.is_set():
                try:
                    children=psutil.Process(process.pid).children(recursive=True)
                    for child in children: child.kill()
                    process.kill()
                except psutil.NoSuchProcess: pass
                if PROFILE=='isolated':
                    subprocess.run(['docker','rm','-f','ecdat-scan-'+job_id],capture_output=True,timeout=15)
                process.wait(timeout=10)
                raise RuntimeError('Job cancelled or parser resource boundary exceeded')
            time.sleep(.15)
        output.seek(0);errors.seek(0)
        if process.returncode:
            raise RuntimeError('Scanner failed: '+errors.read(1500).decode(errors='replace'))
        raw=output.read(8_000_001)
        if len(raw)>8_000_000: raise ValueError('Scanner output exceeds budget')
        result=json.loads(raw)
        for name in ('findings','evidence','coverage','manifest','conflicts'):
            if not isinstance(result.get(name),list): raise ValueError('Invalid scanner response')
        return result

def persist_scan(db, project_id, artifact_id, job_id, result):
    scan=put(db,project_id,'scans',{'artifact_id':artifact_id,'job_id':job_id,**result})
    # IDs from deterministic parsers are scoped to this artifact and run in persisted evidence.
    mapping={e['id']:f"{scan['id']}:{e['id']}" for e in result['evidence']}
    finding_mapping={f['id']:f"{scan['id']}:finding:{f['id']}" for f in result['findings']}
    for kind in ('findings','evidence','coverage','conflicts'):
        for item in result[kind]:
            data={**item,'artifact_id':artifact_id,'scan_id':scan['id'],'job_id':job_id}
            if 'evidence_ids' in data: data['evidence_ids']=[mapping.get(i,i) for i in data['evidence_ids']]
            for claim in ('claim_a','claim_b'):
                if claim in data:data[claim]=finding_mapping.get(data[claim],data[claim])
            data['source_record_id']=data.pop('id',None)
            record_id=mapping.get(item.get('id')) if kind=='evidence' else finding_mapping.get(item.get('id')) if kind=='findings' else None
            put(db,project_id,kind,data,record_id=record_id)
    return scan

def perform(job_id, fence):
    with DB() as db:
        job=db.get(Job,job_id)
        if not job or job.status!='running' or job.fence!=fence or job.lease_until<=time.time():
            return
        project_id,payload,kind=job.project_id,job.payload,job.kind
        if kind=='investigation':
            from .ai import current_policy_view
            investigation=db.get(Record,payload['investigation_id'])
            if not investigation or investigation.project_id!=project_id or current_policy_view(investigation.data).get('status')!='validated':raise ValueError('Investigation authorization no longer applies')
            if (investigation.data.get('suggested_check') or {}).get('check_id')!=payload['check_id']:raise ValueError('Registered check does not match validated request')
            artifacts=rows(db,project_id,'artifacts')
            if payload['check_id']=='compare-artifact-identity':
                result={'status':'completed','comparisons':[{'artifact_id':a['id'],'manifest_matches':manifest(artifact_path(a))==a['manifest']} for a in artifacts]}
            elif payload['check_id']=='refresh-lab-tls':
                eligible=[a for a in artifacts if a.get('authored_fixture')]
                if not eligible:raise ValueError('Registered laboratory artifact is unavailable')
                result={'status':'completed','artifact_id':eligible[-1]['id'],'observation':tls_observation(eligible[-1])}
            else:raise ValueError('Unregistered investigation operation')
            db.refresh(job,with_for_update=True)
            if job.status!='running' or job.fence!=fence or job.lease_until<=time.time():return
            item=put(db,project_id,'investigations',{'parent_id':investigation.id,'check_id':payload['check_id'],**result,'interpretation':'New evidence retained; no automatic conflict resolution or approval'})
            put(db,project_id,'evidence',{'kind':'registered_check','source':'authorized registered controller','excerpt':json.dumps(result)[:6000],'investigation_id':item['id']})
            job.status='completed';job.lease_until=0;job.result={'investigation_id':item['id']};job.message='Registered investigation check completed'
            audit(db,project_id,'worker','investigation.checked',{'record_id':item['id'],'check_id':payload['check_id']});db.commit();return
        if kind=='anchor':
            from .exporting import seal_bundle
            # Linearize cancellation before an irreversible external effect. This
            # conditional write holds the job lock (also in native SQLite) until
            # the bounded sealing operation and its persisted receipt complete.
            admitted=db.execute(update(Job).where(Job.id==job_id,Job.status=='running',Job.fence==fence,Job.lease_until>time.time()).values(message='Committing immutable local-chain receipt'))
            if admitted.rowcount!=1:return
            result=seal_bundle(payload['export_id'])
            db.refresh(job,with_for_update=True)
            if job.status!='running' or job.fence!=fence or job.lease_until<time.time():return
            passport=put(db,project_id,'passports',{'export_id':payload['export_id'],**result,'download_url':f"/api/exports/{payload['export_id']}/passport"})
            job.status='completed' if result.get('status')=='included-local' else 'failed'
            job.result={'passport_id':passport['id'],'anchor_status':result.get('status')};job.message=result.get('error','Local receipt persisted; external finality is not claimed');job.lease_until=0
            audit(db,project_id,'worker','anchor.'+job.status,{'job_id':job_id,'passport_id':passport['id']});db.commit();return
        artifact_row=db.get(Record,payload['artifact_id'])
        if not artifact_row or artifact_row.project_id!=project_id: raise ValueError('Artifact scope mismatch')
        artifact=record_dict(artifact_row)
        if kind=='execute':
            proposal=record_dict(db.get(Record,payload['proposal_id']))
            decision=record_dict(db.get(Record,payload['decision_id']))
            baseline=db.get(Record,proposal['binding']['baseline_scan_id'])
            if not baseline or baseline.project_id!=project_id or baseline.kind!='scans':raise ValueError('Approved baseline is unavailable')
            baseline_content={k:baseline.data[k] for k in ('manifest','coverage','findings','evidence','conflicts')}
            if digest(baseline_content)!=proposal['binding']['baseline_digest']:raise ValueError('Approved baseline evidence has changed')
    before=run_scan(artifact,job_id,fence)
    if kind=='scan':
        result={'scan':before}
    elif kind=='execute':
        if digest({k:before[k] for k in ('manifest','coverage','findings','evidence','conflicts')})!=proposal['binding']['baseline_digest']:
            raise ValueError('Discovery output differs from the reviewed baseline. Re-scan and review a new proposal.')
        candidate=create_candidate(proposal,artifact,decision)
        after=run_scan(candidate,job_id,fence)
        observation=tls_observation(candidate)
        verification=verify_migration(proposal,artifact,candidate,decision,before,after,observation)
        result={'candidate':candidate,'before':before,'after':after,'verification':verification}
    else:
        raise ValueError('Unknown registered job')
    with DB() as db:
        job=db.scalar(select(Job).where(Job.id==job_id).with_for_update())
        if job.status!='running' or job.fence!=fence or job.lease_until<time.time():
            return
        if kind=='scan':
            scan=persist_scan(db,project_id,artifact['id'],job_id,result['scan'])
            job.result={'scan_id':scan['id'],'findings':len(result['scan']['findings']),'coverage':len(result['scan']['coverage'])}
        else:
            candidate=put(db,project_id,'artifacts',result['candidate'])
            scan=persist_scan(db,project_id,candidate['id'],job_id,result['after'])
            verification=put(db,project_id,'verifications',{**result['verification'],'proposal_id':proposal['id'],'decision_id':decision['id'],'candidate_id':candidate['id'],'scan_id':scan['id'],'job_id':job_id})
            job.result={'candidate_id':candidate['id'],'verification_id':verification['id'],'verification_status':verification['status']}
        job.status='completed';job.message='Results persisted';job.lease_until=0
        audit(db,project_id,'worker','job.completed',{'job_id':job_id,'fence':fence,'result':job.result})
        db.commit()

def work_once():
    available=psutil.virtual_memory().available//1024**2
    if available < MEMORY_RESERVE_MB:
        with DB() as db:
            db.execute(update(Job).where(Job.status=='queued').values(message=f'Waiting for memory: {available} MB available, {MEMORY_RESERVE_MB} MB admission floor'))
            db.commit()
        return False
    owner='worker:'+uid()
    if not acquire_resource(owner):return False
    with DB() as db:
        picked=claim(db)
    if not picked:
        release_resource(owner);return False
    job_id,fence=picked
    finished=threading.Event()
    renewal=threading.Thread(target=renew_leases,args=(job_id,fence,owner,finished),daemon=True);renewal.start()
    try:
        perform(job_id,fence)
    except Exception as exc:
        with DB() as db:
            job=db.get(Job,job_id)
            if job and job.status=='running' and job.fence==fence:
                job.status='failed';job.message=str(exc)[:1200];job.lease_until=0
                audit(db,job.project_id,'worker','job.failed',{'job_id':job_id,'reason':job.message})
                db.commit()
    finally:
        finished.set();renewal.join(timeout=2)
        release_resource(owner)
    return True

def worker_loop():
    while not stop_event.is_set():
        try:work_once()
        except Exception:
            import logging
            logging.exception('Worker iteration failed')
        stop_event.wait(1)
