import hashlib
import uuid
import time
from datetime import datetime, timezone

import rfc8785
from sqlalchemy import create_engine, String, Text, Integer, Float, JSON, UniqueConstraint, ForeignKey, event, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from .config import DATABASE_URL

def uid():
    return str(uuid.uuid4())

def now():
    return datetime.now(timezone.utc).isoformat()

def canonical(value):
    return rfc8785.dumps(value)

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String, unique=True)
    password: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String)

class SessionToken(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    csrf: Mapped[str] = mapped_column(String)
    expires: Mapped[float] = mapped_column(Float)

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text, default="")
    disclosure: Mapped[str] = mapped_column(String, default="restricted")
    audit_seq: Mapped[int] = mapped_column(Integer, default=0)
    audit_head: Mapped[str] = mapped_column(String, default="0" * 64)

class Member(Base):
    __tablename__ = "members"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)

class Record(Base):
    __tablename__ = "records"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    kind: Mapped[str] = mapped_column(String, index=True)
    data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(String, default=now)

class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (UniqueConstraint("project_id", "idempotency_key"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    kind: Mapped[str] = mapped_column(String)
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String, default="queued")
    idempotency_key: Mapped[str] = mapped_column(String)
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    fence: Mapped[int] = mapped_column(Integer, default=0)
    lease_until: Mapped[float] = mapped_column(Float, default=0)
    message: Mapped[str] = mapped_column(Text, default="Waiting for one-worker admission")
    created_at: Mapped[str] = mapped_column(String, default=now)
    result: Mapped[dict] = mapped_column(JSON, default=dict)

class Outbox(Base):
    __tablename__ = "outbox"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), unique=True)
    kind: Mapped[str] = mapped_column(String)
    published: Mapped[int] = mapped_column(Integer, default=0)

class Audit(Base):
    __tablename__ = "audit"
    __table_args__ = (UniqueConstraint("project_id", "seq"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict] = mapped_column(JSON)
    previous: Mapped[str] = mapped_column(String)
    hash: Mapped[str] = mapped_column(String)

class ResourceLease(Base):
    __tablename__ = 'resource_leases'
    name: Mapped[str] = mapped_column(String, primary_key=True)
    owner: Mapped[str] = mapped_column(String, default='')
    expires: Mapped[float] = mapped_column(Float, default=0)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False, "timeout": 30} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def sqlite_pragmas(dbapi_connection, _):
        dbapi_connection.execute("PRAGMA journal_mode=WAL")
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

DB = sessionmaker(engine, expire_on_commit=False)

def initialize():
    Base.metadata.create_all(engine)
    from sqlalchemy.exc import IntegrityError
    with DB() as db:
        if not db.get(ResourceLease,'heavy'):
            db.add(ResourceLease(name='heavy',owner='',expires=0))
            try:db.commit()
            except IntegrityError:db.rollback()

def acquire_resource(owner,seconds=180):
    from sqlalchemy import update
    with DB() as db:
        changed=db.execute(update(ResourceLease).where(ResourceLease.name=='heavy',ResourceLease.expires<time.time()).values(owner=owner,expires=time.time()+seconds))
        db.commit()
        return changed.rowcount==1

def release_resource(owner):
    from sqlalchemy import update
    with DB() as db:
        db.execute(update(ResourceLease).where(ResourceLease.name=='heavy',ResourceLease.owner==owner).values(owner='',expires=0));db.commit()

def put(db, project_id, kind, data, record_id=None):
    item = Record(id=record_id or uid(), project_id=project_id, kind=kind, data=data, created_at=now())
    db.add(item)
    db.flush()
    return record_dict(item)

def record_dict(row):
    return {**row.data, "id": row.id, "project_id": row.project_id, "created_at": row.created_at}

def rows(db, project_id, kind, limit=1000):
    return [record_dict(r) for r in db.scalars(select(Record).where(Record.project_id == project_id, Record.kind == kind).order_by(Record.created_at, Record.id).limit(limit))]

def audit(db, project_id, actor, action, details):
    project = db.scalar(select(Project).where(Project.id == project_id).with_for_update())
    db.refresh(project)
    seq = project.audit_seq + 1
    payload = {"schema": "ecdat.audit.v1", "project_id": project_id, "seq": seq, "actor": actor, "action": action, "details": details, "time": now()}
    head = digest({"previous": project.audit_head, "payload": payload})
    db.add(Audit(project_id=project_id, seq=seq, payload=payload, previous=project.audit_head, hash=head))
    project.audit_seq, project.audit_head = seq, head
    db.flush()
    return {"count": seq, "head": head}

def audit_rows(db, project_id):
    return [{"seq": r.seq, "payload": r.payload, "previous": r.previous, "hash": r.hash} for r in db.scalars(select(Audit).where(Audit.project_id == project_id).order_by(Audit.seq))]

def verify_audit(events, checkpoint):
    previous = "0" * 64
    for index, event_row in enumerate(events, 1):
        if event_row["seq"] != index or event_row["payload"].get("seq") != index or event_row["previous"] != previous:
            return False
        previous = digest({"previous": previous, "payload": event_row["payload"]})
        if event_row["hash"] != previous:
            return False
    return checkpoint == {"count": len(events), "head": previous}

def job_dict(j):
    return {"id": j.id, "project_id": j.project_id, "kind": j.kind, "status": j.status, "attempt": j.attempt, "message": j.message, "created_at": j.created_at, "result": j.result, "payload": j.payload}
