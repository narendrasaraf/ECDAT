"""Bounded static discovery. A finding is a located reference, never execution proof."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

VERSION = "ecdat-discovery-0.1"
MAX_FILE_BYTES = 20 * 1024 * 1024


def _id(*parts):
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:24]


def _strict_json(text):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("Duplicate JSON key")
            obj[key] = value
        return obj
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite number")))


class Output:
    def __init__(self):
        self.data = {key: [] for key in ("findings", "evidence", "coverage", "conflicts", "manifest")}

    def add(self, path, line, algorithm, role, parameters, excerpt, kind="static_reference", scope=None):
        evidence_id = _id("evidence", path, line, algorithm, role, excerpt, kind)
        finding_id = _id("finding", path, line, algorithm, role, kind)
        claim = {"algorithm": algorithm, "role": role, "kind": kind, "scope": scope or path}
        self.data["evidence"].append({"id": evidence_id, "path": path, "line": line,
            "excerpt": excerpt[:500], "kind": kind, "source": VERSION})
        finding = {"id": finding_id, "algorithm": algorithm, "role": role, "path": path,
            "line": line, "parameters": parameters, "confidence": "located_reference" if kind == "static_reference" else "direct_metadata",
            "evidence_ids": [evidence_id], "claim": claim}
        self.data["findings"].append(finding)

    def cover(self, path, adapter, status, digest, error=None):
        value = {"path": path, "adapter": adapter, "status": status, "sha256": digest, "version": VERSION}
        if error:
            value["error"] = str(error)[:300]
        self.data["coverage"].append(value)


def _python(text, path, out):
    tree, aliases = ast.parse(text), {}
    # Resolve only imported names; bare familiar-looking identifiers are not proof.
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                aliases[name.asname or name.name.split(".")[0]] = name.name if name.asname else name.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for name in node.names:
                if name.name != "*":
                    aliases[name.asname or name.name] = node.module + "." + name.name
    # Conservative shadow handling: do not attribute an imported name once any
    # local binding can replace it. This may miss an outer reference; it avoids
    # presenting a call on an unrelated object as a confirmed library reference.
    shadowed = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
    shadowed.update(node.arg for node in ast.walk(tree) if isinstance(node, ast.arg))
    shadowed.update(node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    for name in shadowed:
        aliases.pop(name, None)

    def qualified(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, "")
        if isinstance(node, ast.Attribute):
            base = qualified(node.value)
            return base + "." + node.attr if base else ""
        return ""

    def value(node):
        try:
            literal = ast.literal_eval(node)
            if isinstance(literal, bytes):
                return {"state": "known", "byte_length": len(literal), "value": "[bytes withheld]"}
            if isinstance(literal, (str, int, float, bool)) or literal is None:
                return {"state": "known", "value": literal if not isinstance(literal, str) else literal[:100]}
        except (ValueError, TypeError, SyntaxError):
            pass
        return {"state": "unknown", "expression": (ast.get_source_segment(text, node) or "")[:100]}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name, algorithm, role = qualified(node.func), None, None
        last = name.split(".")[-1]
        if name.startswith("hashlib.") and last in {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"}:
            algorithm, role = last.upper(), "hash"
        elif name == "hashlib.new":
            algorithm = str(value(node.args[0]).get("value", "UNKNOWN_HASH")).upper() if node.args else "UNKNOWN_HASH"
            role = "hash"
        elif name.startswith("cryptography.hazmat.primitives.ciphers.algorithms."):
            algorithm, role = last.upper(), "encryption"
        elif name.startswith("cryptography.hazmat.primitives.hashes.") and last in {"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_512"}:
            algorithm, role = last, "hash"
        elif name.startswith("cryptography.hazmat.primitives.asymmetric."):
            family = name.split(".")[4].lower()
            families = {"rsa": ("RSA", "key_generation"), "ec": ("EC", "key_generation"), "ed25519": ("Ed25519", "signature"), "ed448": ("Ed448", "signature"), "x25519": ("X25519", "key_exchange"), "x448": ("X448", "key_exchange")}
            if family in families and last in {"generate_private_key", "generate", "from_private_bytes", "from_public_bytes"}:
                algorithm, role = families[family]
        elif name.startswith(("Crypto.Cipher.", "Cryptodome.Cipher.")) and last == "new":
            algorithm, role = name.split(".")[-2].upper(), "encryption"
        elif name.startswith(("Crypto.PublicKey.", "Cryptodome.PublicKey.")) and last in {"generate", "import_key"}:
            algorithm, role = name.split(".")[-2].upper(), "key_generation"
        if not algorithm:
            continue
        # Never include key material or input messages in excerpts/parameters.
        params = {"call": name, "argument_count": len(node.args)}
        safe_keywords = {"key_size", "public_exponent", "length", "iterations", "backend"}
        for kw in node.keywords:
            params[kw.arg or "dynamic_kwargs"] = value(kw.value) if kw.arg in safe_keywords else {"state": "withheld"}
        if algorithm == "RSA" and node.args:
            params["first_argument"] = value(node.args[0])
        out.add(path, node.lineno, algorithm, role, params, f"{name}(…) — arguments redacted")


def _js(text, path, out):
    from tree_sitter import Language, Parser
    if path.endswith((".ts", ".tsx")):
        import tree_sitter_typescript as grammar
        language = grammar.language_tsx() if path.endswith(".tsx") else grammar.language_typescript()
    else:
        import tree_sitter_javascript as grammar
        language = grammar.language()
    parser = Parser(Language(language))
    source = text.encode("utf8")
    tree = parser.parse(source)
    if tree.root_node.has_error:
        raise ValueError("JS/TS grammar parse error; findings withheld")
    aliases, namespaces = {}, set()
    def src(node):
        return source[node.start_byte:node.end_byte].decode("utf8") if node else ""
    def walk(node):
        yield node
        for child in node.named_children:
            yield from walk(child)
    nodes = list(walk(tree.root_node))
    for node in nodes:
        if node.type == "import_statement":
            module = node.child_by_field_name("source")
            if src(module).strip("\"'") not in {"crypto", "node:crypto"}:
                continue
            for child in walk(node):
                if child.type == "import_specifier":
                    name = src(child.child_by_field_name("name"))
                    alias = src(child.child_by_field_name("alias")) or name
                    aliases[alias] = name
                elif child.type == "namespace_import":
                    identifiers = [n for n in child.named_children if n.type == "identifier"]
                    namespaces.update(src(n) for n in identifiers)
                elif child.type == "import_clause":
                    namespaces.update(src(n) for n in child.named_children if n.type == "identifier")
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is None or value.type != "call_expression" or src(value.child_by_field_name("function")) != "require":
                continue
            args = value.child_by_field_name("arguments")
            if len(args.named_children) != 1 or src(args.named_children[0]).strip("\"'") not in {"crypto", "node:crypto"}:
                continue
            name = node.child_by_field_name("name")
            if name.type == "identifier":
                namespaces.add(src(name))
            elif name.type == "object_pattern":
                for child in name.named_children:
                    if child.type == "shorthand_property_identifier_pattern":
                        aliases[src(child)] = src(child)
                    elif child.type == "pair_pattern":
                        aliases[src(child.child_by_field_name("value"))] = src(child.child_by_field_name("key"))
    shadowed = set()
    for node in nodes:
        if node.type == "formal_parameters":
            shadowed.update(src(child) for child in walk(node) if child.type in {"identifier", "shorthand_property_identifier_pattern"})
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left and left.type == "identifier":
                shadowed.add(src(left))
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            is_crypto_require = value is not None and value.type == "call_expression" and src(value.child_by_field_name("function")) == "require" and any(src(arg).strip("\"'") in {"crypto", "node:crypto"} for arg in value.child_by_field_name("arguments").named_children)
            name = node.child_by_field_name("name")
            if not is_crypto_require and name and name.type == "identifier":
                shadowed.add(src(name))
    for name in shadowed:
        aliases.pop(name, None)
        namespaces.discard(name)
    operations = {"createHash": "hash", "createHmac": "mac", "createCipheriv": "encryption", "createDecipheriv": "encryption", "generateKeyPairSync": "key_generation", "generateKeyPair": "key_generation", "createSign": "signature", "createVerify": "signature"}
    for node in nodes:
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        name = src(function)
        operation = aliases.get(name)
        if function.type == "member_expression":
            obj = src(function.child_by_field_name("object"))
            if obj in namespaces:
                operation = src(function.child_by_field_name("property"))
        if operation not in operations:
            continue
        args = node.child_by_field_name("arguments").named_children
        known = bool(args and args[0].type == "string")
        algorithm = src(args[0])[1:-1] if known else "UNKNOWN"
        params = {"call": f"node:crypto.{operation}", "algorithm": {"state": "known" if known else "unknown"}}
        out.add(path, node.start_point.row + 1, algorithm.upper(), operations[operation], params, f"node:crypto.{operation}(…) — arguments redacted")


def _certificate(raw, path, out):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
    if b"PRIVATE KEY" in raw:
        return "protected", "Private key content is not exposed or parsed as a certificate"
    cert = None
    try:
        cert = x509.load_pem_x509_certificate(raw) if b"BEGIN CERTIFICATE" in raw else x509.load_der_x509_certificate(raw)
        key = cert.public_key()
    except ValueError:
        key = serialization.load_pem_public_key(raw) if b"BEGIN PUBLIC KEY" in raw or b"BEGIN RSA PUBLIC KEY" in raw else serialization.load_der_public_key(raw)
    name = next((label for cls, label in [(rsa.RSAPublicKey, "RSA"), (ec.EllipticCurvePublicKey, "EC"), (ed25519.Ed25519PublicKey, "Ed25519"), (ed448.Ed448PublicKey, "Ed448"), (dsa.DSAPublicKey, "DSA")] if isinstance(key, cls)), type(key).__name__)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    parameters = {"key_size": getattr(key, "key_size", None), "spki_sha256": hashlib.sha256(spki).hexdigest()}
    if cert:
        parameters.update(signature_oid=cert.signature_algorithm_oid.dotted_string, not_before=cert.not_valid_before_utc.isoformat(), not_after=cert.not_valid_after_utc.isoformat())
    out.add(path, 1, name, "authentication" if cert else "unknown", parameters, "Public-key metadata; no private material", "certificate_metadata" if cert else "public_key_metadata")
    return ("partial", "Only first certificate in chain inspected") if raw.count(b"BEGIN CERTIFICATE") > 1 else ("complete", None)


def _structured(text, path, out):
    obj = _strict_json(text)
    if not isinstance(obj, dict):
        return "unsupported", "JSON is not a supported configuration or attributed metadata record"
    scope = obj.get("scope", obj.get("service", path))
    if isinstance(obj.get("tls"), dict):
        tls = obj["tls"]
        groups = tls.get("groups", [])
        if not isinstance(groups, list) or any(not isinstance(g, str) for g in groups):
            raise ValueError("tls.groups must be a string array")
        for group in groups:
            out.add(path, 1, group, "key_exchange", {"minVersion": tls.get("minVersion"), "policy": tls.get("policy", "unspecified")}, f"TLS configured group: {group}", "configuration", scope)
        auth = obj.get("auth", obj.get("authentication", {}))
        if isinstance(auth, dict) and auth.get("algorithm"):
            out.add(path, 1, str(auth["algorithm"]), "authentication", {}, "Declared authentication algorithm", "configuration", scope)
        return "complete", None
    if obj.get("kind") in {"tls_observation", "supplier_metadata", "cloud_metadata", "hsm_metadata"}:
        if not obj.get("source") or not isinstance(obj.get("assertions"), list):
            raise ValueError("Metadata import requires source and assertions")
        for assertion in obj["assertions"]:
            if not isinstance(assertion, dict) or not all(isinstance(assertion.get(k), str) for k in ("algorithm", "role")):
                raise ValueError("Malformed metadata assertion")
            # Imported observation is attributed input, not a newly executed probe.
            kind = "imported_observation" if obj["kind"] == "tls_observation" else "imported_declaration"
            out.add(path, 1, assertion["algorithm"], assertion["role"], {"attributed_source": obj["source"], "observed_at": obj.get("observed_at"), "expectation": assertion.get("expectation", False)}, "Attributed metadata import", kind, scope)
        return "complete", None
    return "unsupported", "No supported TLS or attributed metadata schema"


def _elf(raw, path, out):
    from io import BytesIO
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    elf = ELFFile(BytesIO(raw))
    count = 0
    rules = [(r"(?:^|_)RSA(?:_|$)", "RSA"), (r"(?:^|_)AES(?:_|$)", "AES"), (r"(?:^|_)SHA256(?:_|$)", "SHA256"), (r"(?:^|_)EVP_(?:PKEY|CIPHER|DIGEST)", "OPENSSL_GENERIC")]
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                for pattern, algorithm in rules:
                    if re.search(pattern, symbol.name, re.I):
                        out.add(path, None, algorithm, "unknown", {"symbol": symbol.name, "elf_class": elf.elfclass}, symbol.name, "symbol_presence")
                        count += 1
                        break
    return "partial", f"Selected ELF symbol metadata only; {count} references; stripped/dynamic behavior unresolved"


def _conflicts(out):
    findings = out.data["findings"]
    for declared in findings:
        claim = declared["claim"]
        if claim["kind"] not in {"configuration", "imported_declaration"}:
            continue
        strict = declared["parameters"].get("policy") == "strict" or declared["parameters"].get("expectation") is True
        if not strict:
            continue
        for observed in findings:
            other = observed["claim"]
            if other["kind"] != "imported_observation" or other["scope"] != claim["scope"] or other["role"] != claim["role"] or other["algorithm"] == claim["algorithm"]:
                continue
            allowed = {item["algorithm"] for item in findings if item["path"] == declared["path"] and item["role"] == declared["role"] and item["claim"]["kind"] == claim["kind"]}
            if observed["algorithm"] in allowed:
                continue
            out.data["conflicts"].append({"id": _id("conflict", declared["id"], observed["id"]), "claim_a": declared["id"], "claim_b": observed["id"], "reason": "Declared expectation differs from attributed observation in the same role/scope; temporal applicability requires review", "evidence_ids": declared["evidence_ids"] + observed["evidence_ids"]})


def scan_directory(path: Path, *, enable_syft: bool | None = None) -> dict:
    root, out = Path(path).resolve(), Output()
    if not root.is_dir():
        raise ValueError("Scan input must be a directory")
    files = sorted(root.rglob("*"))
    if len(files) > 10000:
        raise ValueError("Scan entry limit exceeded")
    for file in files:
        relative = file.relative_to(root).as_posix()
        if file.is_symlink():
            out.cover(relative, "intake", "failed", None, "Symlink rejected")
            continue
        if not file.is_file():
            continue
        if not file.resolve().is_relative_to(root):
            out.cover(relative, "intake", "failed", None, "Path escaped scan root")
            continue
        size = file.stat().st_size
        if size > MAX_FILE_BYTES:
            out.cover(relative, "intake", "failed", None, "File exceeds bounded adapter size")
            out.data["manifest"].append({"path": relative, "size": size, "sha256": None})
            continue
        raw = file.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        out.data["manifest"].append({"path": relative, "size": len(raw), "sha256": digest})
        suffix = file.suffix.lower()
        adapter, status, error = "unsupported", "unsupported", "No documented adapter for this file"
        try:
            if suffix == ".py":
                adapter = "python_ast"
                _python(raw.decode("utf8"), relative, out)
                status, error = "complete", None
            elif suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
                adapter = "javascript_ast"
                _js(raw.decode("utf8"), relative, out)
                status, error = "complete", None
            elif suffix in {".pem", ".crt", ".cer", ".der", ".key", ".pub"}:
                adapter = "x509"
                status, error = _certificate(raw, relative, out)
            elif raw.startswith(b"\x7fELF"):
                adapter = "elf_symbols"
                status, error = _elf(raw, relative, out)
            elif suffix == ".json":
                adapter = "structured_metadata"
                status, error = _structured(raw.decode("utf8"), relative, out)
        except ImportError as exc:
            status, error = "unavailable", f"Adapter dependency unavailable: {exc.name}"
        except Exception as exc:
            # Malformed ELF/cert parsers use their own exception classes. Preserve
            # this file's failure without losing other adapters' completed evidence.
            status, error = "failed", f"{type(exc).__name__}: {str(exc)[:240]}"
        out.cover(relative, adapter, status, digest, error)
    enabled = enable_syft if enable_syft is not None else os.environ.get("ECDAT_ENABLE_SYFT") == "1"
    if enabled:
        inventory = scan_syft(root)
        out.cover(".", "syft_inventory", inventory["status"], None, inventory.get("error"))
        for package in inventory.get("packages", []):
            name = str(package.get("name", "unknown"))
            eid = _id("package", name, package.get("version"), package.get("type"))
            out.data["evidence"].append({"id": eid, "path": ".", "line": None, "excerpt": f"{name} {package.get('version', 'unknown')}", "kind": "package_presence", "source": "syft", "package": {key: package.get(key) for key in ("name", "version", "type", "purl")}})
        for archive in files:
            if archive.is_file() and not archive.is_symlink() and archive.name.endswith((".oci.tar", ".oci.tar.gz")):
                relative = archive.relative_to(root).as_posix()
                inventory = scan_syft(archive, source_type="oci-archive")
                out.cover(relative, "syft_oci_inventory", inventory["status"], None, inventory.get("error"))
                for package in inventory.get("packages", []):
                    name = str(package.get("name", "unknown"))
                    out.data["evidence"].append({"id": _id("package", relative, name, package.get("version")), "path": relative, "line": None, "excerpt": f"{name} {package.get('version', 'unknown')}", "kind": "package_presence", "source": "syft-oci", "package": {key: package.get(key) for key in ("name", "version", "type", "purl")}})
    else:
        out.cover(".", "syft_inventory", "unavailable" if not shutil.which("syft") else "not_run", None,
                  "Syft is not installed" if not shutil.which("syft") else "Available; run only through the authorized isolated Syft adapter")
    _conflicts(out)
    return out.data


def scan_syft(path: Path, timeout: int = 60, source_type: str = "dir") -> dict:
    """Controller-only optional adapter. Run in its no-network sandbox, never build input."""
    tool = shutil.which("syft")
    if not tool:
        return {"status": "unavailable", "packages": [], "error": "Syft is not installed"}
    if source_type not in {"dir", "oci-archive"}:
        raise ValueError("Only local directory or OCI-archive inventory is supported")
    try:
        import tempfile
        import time
        # Disk-backed bounded output avoids accumulating an unbounded SBOM in RAM.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            environment = {key: value for key, value in os.environ.items() if key in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
            environment.update(SYFT_CHECK_FOR_APP_UPDATE="false", SYFT_PARALLELISM="1")
            process = subprocess.Popen([tool, f"{source_type}:{Path(path).resolve()}", "-o", "syft-json"], stdout=output, stderr=errors, env=environment)
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if time.monotonic() > deadline or output.tell() > 8_000_000 or errors.tell() > 1_000_000:
                    process.kill()
                    process.wait(timeout=5)
                    return {"status": "failed", "packages": [], "error": "Syft time or output budget exceeded"}
                time.sleep(.05)
            output.seek(0)
            errors.seek(0)
            if process.returncode:
                return {"status": "failed", "packages": [], "error": errors.read(300).decode(errors="replace")}
            raw = output.read(8_000_001)
            if len(raw) > 8_000_000:
                return {"status": "failed", "packages": [], "error": "Syft output budget exceeded"}
        payload = _strict_json(raw)
        return {"status": "complete", "packages": payload.get("artifacts", []), "source": "syft_package_presence", "raw_sha256": hashlib.sha256(raw).hexdigest()}
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {"status": "failed", "packages": [], "error": str(exc)[:300]}
