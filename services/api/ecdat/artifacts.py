import base64
import hashlib
import json
import os
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .config import STATE
from .store import canonical, digest, uid

def manifest(directory):
    result = []
    for path in sorted(Path(directory).rglob("*")):
        if path.is_symlink():
            raise ValueError("Symlinks cannot be included")
        if path.is_file():
            data = path.read_bytes()
            result.append({"path": path.relative_to(directory).as_posix(), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    return result

def artifact_path(artifact):
    path = (STATE / "artifacts" / artifact["storage_id"]).resolve()
    if not path.is_relative_to((STATE / "artifacts").resolve()):
        raise ValueError("Invalid storage identity")
    return path

def finalize(directory, *, name, authored=False, source_id=None):
    files = manifest(directory)
    storage_id = uid()
    target = STATE / "artifacts" / storage_id
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(directory), target)
    return {"name": name, "storage_id": storage_id, "manifest": files, "manifest_digest": digest(files), "authored_fixture": authored, "source_id": source_id, "status": "ready"}

def fixture_certificate():
    secrets = STATE / "lab-secrets"
    secrets.mkdir(exist_ok=True)
    key_path, cert_path = secrets / "server-key.pem", secrets / "server-cert.pem"
    if not key_path.exists() or not cert_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        if os.name != "nt":
            key_path.chmod(0o600)
    return key_path, cert_path

def create_demo_artifact():
    staging = STATE / "staging" / uid()
    staging.mkdir(parents=True)
    _, cert = fixture_certificate()
    (staging / "server.pem").write_bytes(cert.read_bytes())
    (staging / "tls.json").write_bytes(canonical({"service": "lab-tls-01", "tls": {"groups": ["X25519"], "minVersion": "TLSv1.3"}, "authentication": {"algorithm": "RSA", "bits": 2048}}))
    (staging / "payments.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa as signing\nkey = signing.generate_private_key(public_exponent=65537, key_size=2048)\n# SHA1 in a comment is not a cryptographic operation.\n", encoding="utf-8")
    (staging / "gateway.ts").write_text("import { createHash as hash } from 'node:crypto';\nexport const checksum = hash('sha256').update('authored fixture').digest('hex');\n", encoding="utf-8")
    (staging / "supplier-claim.json").write_bytes(canonical({"scope":"lab-tls-01","tls":{"groups":["X25519MLKEM768"],"policy":"strict"},"source":"Authored supplier expectation; applicability requires review"}))
    (staging / "historical-observation.json").write_bytes(canonical({"kind":"tls_observation","scope":"lab-tls-01","source":"Authored historical example, not a live measurement","observed_at":"2026-09-18T16:00:00Z","assertions":[{"algorithm":"X25519","role":"key_exchange"},{"algorithm":"RSA","role":"authentication"}]}))
    (staging / "README.txt").write_text("Authored lab. Public demo context. TLS certificate authentication remains RSA after key-exchange migration. No source code is executed by discovery.\n", encoding="utf-8")
    return finalize(staging, name="Payment gateway · authored baseline", authored=True)

def snapshot_files(artifact):
    directory = artifact_path(artifact)
    files = []
    for entry in manifest(directory):
        data = (directory / entry["path"]).read_bytes()
        protected=b"PRIVATE KEY-----" in data or Path(entry['path']).suffix.lower()=='.key'
        if not protected:
            for loader in (serialization.load_der_private_key,serialization.load_pem_private_key):
                try:
                    loader(data,password=None)
                    protected=True;break
                except TypeError:
                    # Encrypted private key structures are protected too.
                    protected=True;break
                except ValueError:
                    pass
        if protected:
            files.append({**entry, "availability": "withheld_private_material"})
        else:
            files.append({**entry, "availability": "included", "encoding": "base64", "content": base64.b64encode(data).decode()})
    return files
