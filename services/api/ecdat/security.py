import hashlib
import secrets
import time
from collections import defaultdict, deque
from threading import Lock

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Request, HTTPException
from sqlalchemy import select
from .store import DB, User, SessionToken, Member, Project

hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
attempts = defaultdict(deque)
attempt_lock = Lock()

def error(status, code, message, details=None):
    raise HTTPException(status, {"code": code, "message": message, "details": details})

def throttle(key):
    with attempt_lock:
        q = attempts[key]
        while q and q[0] < time.time() - 60:
            q.popleft()
        if len(q) >= 8:
            error(429, "login_throttled", "Too many attempts. Try again in a minute.")
        q.append(time.time())

def identity(request: Request):
    token = request.cookies.get("ecdat_session", "")
    with DB() as db:
        session = db.get(SessionToken, hashlib.sha256(token.encode()).hexdigest())
        if not session or session.expires < time.time():
            error(401, "unauthenticated", "Sign in to continue.")
        user = db.get(User, session.user_id)
        if request.method not in ("GET", "HEAD", "OPTIONS") and not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session.csrf):
            error(403, "csrf", "Request token is missing or invalid.")
        return {"id": user.id, "username": user.username, "role": user.role, "csrf_token": session.csrf}

def require_role(user, *roles):
    if user["role"] not in roles:
        error(403, "role_forbidden", "Your role cannot perform this action.")

def project_access(db, project_id, user):
    project = db.get(Project, project_id)
    if not project or not db.get(Member, (project_id, user["id"])):
        error(404, "not_found", "Project not found.")
    return project

def record_access(db, cls, record_id, user, kind=None):
    row = db.get(cls, record_id)
    if not row or (kind and row.kind != kind):
        error(404, "not_found", "Record not found.")
    project_access(db, row.project_id, user)
    return row
