import io
import json
from pathlib import Path
import stat
import tarfile
import zipfile

import pytest

from ecdat.discovery import scan_directory, safe_extract_archive, validate_archive, IntakeLimits


def test_python_alias_location_unknown_and_comments(tmp_path):
    (tmp_path / "sample.py").write_text("# hashlib.md5(b'comment')\nimport hashlib as h\nfrom cryptography.hazmat.primitives.asymmetric import rsa as keygen\nh.md5(b'secret')\nkeygen.generate_private_key(public_exponent=65537, key_size=unknown_size)\n", encoding="utf8")
    result = scan_directory(tmp_path)
    assert [(f["algorithm"], f["line"]) for f in result["findings"]] == [("MD5", 4), ("RSA", 5)]
    assert result["findings"][1]["parameters"]["key_size"]["state"] == "unknown"
    assert "secret" not in json.dumps(result)
    assert next(c for c in result["coverage"] if c["path"] == "sample.py")["status"] == "complete"


@pytest.mark.parametrize("filename,content", [
    ("source.js", "import {createHash as hash} from 'node:crypto';\n// createHash('md5')\nhash('sha256');"),
    ("source.ts", "import * as crypto from 'crypto';\nconst algorithm: string = 'md5';\ncrypto.createHash(algorithm);"),
    ("source.cjs", "const {createHash: hash} = require('crypto'); hash('sha384');"),
])
def test_real_js_ts_grammar(tmp_path, filename, content):
    (tmp_path / filename).write_text(content, encoding="utf8")
    result = scan_directory(tmp_path)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["algorithm"] in {"SHA256", "UNKNOWN", "SHA384"}
    assert result["coverage"][0]["status"] == "complete"


def test_syntax_failure_and_duplicate_json_visible(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:", encoding="utf8")
    (tmp_path / "broken.json").write_text('{"tls":{},"tls":{}}', encoding="utf8")
    result = scan_directory(tmp_path)
    assert len([item for item in result["coverage"] if item["status"] == "failed"]) == 2
    assert len(result["manifest"]) == 2


def test_imported_observation_retains_roles_and_mismatch(tmp_path):
    (tmp_path / "tls.json").write_text(json.dumps({"scope": "service-a", "tls": {"groups": ["X25519MLKEM768"], "policy": "strict"}, "auth": {"algorithm": "RSA"}}))
    (tmp_path / "observation.json").write_text(json.dumps({"kind": "tls_observation", "scope": "service-a", "source": "authored-test", "assertions": [{"algorithm": "X25519", "role": "key_exchange"}, {"algorithm": "RSA", "role": "authentication"}]}))
    result = scan_directory(tmp_path)
    assert len(result["conflicts"]) == 1
    assert len(result["findings"]) == 4
    assert "temporal" in result["conflicts"][0]["reason"]
    config = {"scope": "service-a", "tls": {"groups": ["X25519MLKEM768", "X25519"], "policy": "strict"}}
    (tmp_path / "tls.json").write_text(json.dumps(config))
    assert not scan_directory(tmp_path)["conflicts"]


def test_certificate_metadata_and_private_key_redacted(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.local")])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256())
    (tmp_path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "secret.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    result = scan_directory(tmp_path)
    assert result["findings"][0]["algorithm"] == "RSA"
    assert result["findings"][0]["role"] == "authentication"
    assert any(c["status"] == "protected" for c in result["coverage"])
    assert "BEGIN PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "C:/drive", "a\\escape", "CON.txt", "a/../bad", "a./file"])
def test_zip_unsafe_names_rejected_before_extract(tmp_path, name):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as source:
        source.writestr(name, "data")
    if "\\" in name:
        # Windows ZipInfo normalizes backslashes when authoring archives. Restore
        # the hostile name in both same-length local/central header name fields.
        archive.write_bytes(archive.read_bytes().replace(name.replace("\\", "/").encode(), name.encode()))
    output = tmp_path / "staging"
    assert safe_extract_archive(archive, output)["ok"] is False
    assert not output.exists()


def test_zip_symlink_duplicate_and_limits(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as source:
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        source.writestr(link, "../escape")
    assert not validate_archive(archive)["ok"]
    with zipfile.ZipFile(archive, "w") as source:
        source.writestr("A.py", "x")
        source.writestr("a.py", "x")
    assert not validate_archive(archive)["ok"]
    with zipfile.ZipFile(archive, "w") as source:
        source.writestr("file", "12345")
    assert not validate_archive(archive, IntakeLimits(max_file_bytes=4))["ok"]


def test_tar_link_rejected_and_good_archive_hashed(tmp_path):
    archive = tmp_path / "input.tar"
    with tarfile.open(archive, "w") as source:
        item = tarfile.TarInfo("link")
        item.type, item.linkname = tarfile.SYMTYPE, "../escape"
        source.addfile(item)
    assert not validate_archive(archive)["ok"]
    good = tmp_path / "good.zip"
    with zipfile.ZipFile(good, "w") as source:
        source.writestr("sub/code.py", "import hashlib\nhashlib.sha256()")
    result = safe_extract_archive(good, tmp_path / "new")
    assert result["ok"] and len(result["manifest"][0]["sha256"]) == 64
    assert scan_directory(tmp_path / "new")["findings"][0]["algorithm"] == "SHA256"


def test_stable_ids_and_scope_preserved(tmp_path):
    (tmp_path / "input.py").write_text("import hashlib\nhashlib.sha256()")
    assert scan_directory(tmp_path) == scan_directory(tmp_path)


def test_shadowed_imports_are_not_library_findings(tmp_path):
    (tmp_path / "shadow.py").write_text("import hashlib as h\ndef f(h):\n    h.md5()\n")
    (tmp_path / "shadow.js").write_text("import * as crypto from 'node:crypto'; function f(crypto) { crypto.createHash('md5'); }")
    assert not scan_directory(tmp_path)["findings"]


def test_malformed_elf_does_not_discard_other_files(tmp_path):
    (tmp_path / "bad.elf").write_bytes(b"\x7fELF\x02\x01broken")
    (tmp_path / "ok.py").write_text("import hashlib\nhashlib.sha256()")
    result = scan_directory(tmp_path)
    assert result["findings"][0]["algorithm"] == "SHA256"
    assert next(c for c in result["coverage"] if c["path"] == "bad.elf")["status"] == "failed"
