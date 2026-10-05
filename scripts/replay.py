"""Offline, bounded replay. No ECDAT connection or supplied-code execution."""
import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
import uuid

import rfc8785
from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
MAX_RESTORED_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 20 * 1024 * 1024
FINDING_FIELDS = ('path', 'line', 'algorithm', 'role', 'parameters', 'confidence', 'claim')
EVIDENCE_FIELDS = ('path', 'line', 'excerpt', 'kind', 'source', 'package')
COVERAGE_FIELDS = ('path', 'adapter', 'status', 'sha256', 'version')
SCAN_FIELDS = ('manifest', 'coverage', 'findings', 'evidence', 'conflicts')
EXTERNAL_ADAPTERS = {'syft_inventory', 'syft_oci_inventory'}


def digest(value):
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def strict_json(text):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite number')))


def normalized(items, fields):
    # Multisets preserve duplicate counts; database/run IDs are intentionally absent.
    return Counter(rfc8785.dumps({key: item.get(key) for key in fields}).decode() for item in items)


def difference(expected, actual):
    return {'missing': [json.loads(value) for value in list((expected - actual).elements())[:20]],
            'unexpected': [json.loads(value) for value in list((actual - expected).elements())[:20]],
            'expected_count': sum(expected.values()), 'actual_count': sum(actual.values())}


def safe_path(value):
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ValueError('Invalid snapshot path')
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in ('.', '..') for part in path.parts):
        raise ValueError('Noncanonical or escaping snapshot path')
    for part in path.parts:
        if any(ord(char) < 32 or char in '\\:<>"|?*' for char in part) or part.endswith((' ', '.')):
            raise ValueError('Unsafe cross-platform path')
        if re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', part, re.I):
            raise ValueError('Reserved device path')
    return path


def manifest_index(entries):
    if not isinstance(entries, list) or len(entries) > 10000:
        raise ValueError('Invalid or oversized manifest')
    result, folded = {}, set()
    for entry in entries:
        path = safe_path(entry['path']).as_posix()
        if path.casefold() in folded:
            raise ValueError('Duplicate or case-colliding path')
        folded.add(path.casefold())
        if type(entry['size']) is not int or not 0 <= entry['size'] <= MAX_FILE_BYTES:
            raise ValueError('Invalid or oversized snapshot entry')
        if not isinstance(entry['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', entry['sha256']):
            raise ValueError('Invalid file digest')
        result[path] = {key: entry[key] for key in ('path', 'sha256', 'size')}
    if sum(entry['size'] for entry in result.values()) > MAX_RESTORED_BYTES:
        raise ValueError('Restoration byte limit exceeded')
    for path in result:
        if any(parent.as_posix().casefold() in folded for parent in PurePosixPath(path).parents if parent.as_posix() != '.'):
            raise ValueError('File/directory path collision')
    return result


def scan_restored(directory, isolated=False):
    # Fresh process and state directory; disable external adapters explicitly.
    env = {**os.environ, 'PYTHONPATH': str(ROOT / 'services/api'),
           'ECDAT_ENABLE_SYFT': '0', 'ECDAT_STATE': str(directory.parent / 'state'),
           'ECDAT_DATABASE_URL': 'sqlite:///:memory:'}
    output, errors = directory.parent / 'scan-output.json', directory.parent / 'scan-errors.txt'
    name = 'ecdat-replay-' + uuid.uuid4().hex
    command = [sys.executable, '-m', 'ecdat.scan_runner', str(directory)]
    if isolated:
        command = ['docker','run','--rm','--name',name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--cpus','1','--pids-limit','96','--tmpfs','/tmp:rw,noexec,nosuid,size=128m','--user','65532:65532','--mount',f'type=bind,source={directory.resolve()},target=/input,readonly','ecdat-scanner:local']
        env = {k:v for k,v in os.environ.items() if k in ('PATH','SYSTEMROOT','WINDIR','TEMP','TMP','USERPROFILE')}
    with output.open('wb') as stdout, errors.open('wb') as stderr:
        process = subprocess.Popen(command, env=env, cwd=directory.parent, stdout=stdout, stderr=stderr,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        started = time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic()-started > 100 or output.stat().st_size > 8_000_000 or errors.stat().st_size > 1_000_000:
                    raise ValueError('Fresh scanner exceeded time or output limit')
                time.sleep(.15)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            if isolated:
                subprocess.run(['docker','rm','-f',name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    if process.returncode or output.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('Fresh scanner failed or exceeded output limit')
    return strict_json(output.read_text(encoding='utf-8'))


def validate_cbom(value):
    registry = Registry()
    for path in (ROOT / 'schemas').glob('*.json'):
        resource = Resource.from_contents(strict_json(path.read_text(encoding='utf-8')))
        registry = registry.with_resource('http://cyclonedx.org/schema/' + path.name, resource)
    schema = strict_json((ROOT / 'schemas/bom-1.6.schema.json').read_text(encoding='utf-8'))
    Draft7Validator(schema, registry=registry).validate(value)


def verify_audit(events, checkpoint):
    previous = '0' * 64
    for index, event in enumerate(events, 1):
        if event['seq'] != index or event['payload'].get('seq') != index or event['previous'] != previous:
            return False
        previous = digest({'previous': previous, 'payload': event['payload']})
        if event['hash'] != previous:
            return False
    return checkpoint == {'count': len(events), 'head': previous}


def tls_outcomes(observation, fallback):
    hybrid = observation.get('hybrid', [])
    classical = observation.get('classical', {})
    rejections = {'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE', 'ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE', 'ERR_SSL_NO_SUITABLE_KEY_SHARE', 'ERR_SSL_NO_SHARED_CIPHER'}
    return {
        'hybrid_observed': len(hybrid) == 8 and all(x.get('connected') and x.get('group') == 'X25519MLKEM768' for x in hybrid),
        'authenticated_payload': len(hybrid) == 8 and all(x.get('authorized') and x.get('payload_ok') and x.get('authentication') == 'RSA' and x.get('protocol') == 'TLSv1.3' for x in hybrid),
        'peer_policy': bool(classical.get('connected') and classical.get('group') == 'X25519' and classical.get('authorized') and classical.get('payload_ok')) if fallback else bool(not classical.get('connected') and classical.get('error') in rejections),
    }


def fresh_tls(config):
    """Only our fixed loopback harness runs; supplied source and targets never run."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import shutil
    bundled = Path.home() / '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe'
    node = os.getenv('ECDAT_NODE') or (str(bundled) if bundled.exists() else shutil.which('node'))
    if not node:
        raise RuntimeError('Node 24 with hybrid TLS support is required')
    with tempfile.TemporaryDirectory(prefix='ecdat-fresh-tls-') as temporary:
        folder = Path(temporary)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
        key_path, cert_path, config_path = folder/'key.pem', folder/'cert.pem', folder/'tls.json'
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        if os.name != 'nt': key_path.chmod(0o600)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        # Discard all other supplied configuration fields, including potential targets.
        config_path.write_text(json.dumps({'tls': {'groups': config['tls']['groups']}}), encoding='utf-8')
        process = subprocess.run([node, str(ROOT/'packages/verification/tls-lab.mjs'), str(config_path), str(key_path), str(cert_path)], capture_output=True, text=True, timeout=30)
        if process.returncode or len(process.stdout) > 1024*1024:
            raise RuntimeError('Registered local TLS harness unavailable or failed')
        return strict_json(process.stdout)


def replay_tls(bundle, proposals, add):
    if len(bundle['verifications']) > 16:
        add('registered_tls_replay', 'unavailable', detail='At most 16 registered TLS verifications can be replayed per bundle.')
        return
    for verification in bundle['verifications']:
        proposal = proposals.get(verification.get('proposal_id'))
        if not proposal or proposal['binding'].get('recipe') != 'tls-hybrid' or proposal['binding'].get('recipe_version') != '1':
            add('registered_tls_replay', 'unavailable', detail='No supported bound TLS recipe.')
            continue
        binding = proposal['binding']
        fallback = binding.get('fallback')
        config = proposal.get('after', {})
        groups = ['X25519MLKEM768', 'X25519'] if fallback is True else ['X25519MLKEM768']
        if type(fallback) is not bool or config.get('tls', {}).get('groups') != groups or digest(config) != binding.get('after_digest'):
            raise ValueError('TLS configuration differs from bound recipe policy')
        decision = next((d for d in bundle['decisions'] if d['id'] == verification.get('decision_id')), None)
        if not decision or decision.get('action') != 'approve' or decision.get('proposal_id') != proposal['id']:
            raise ValueError('TLS verification lacks its bound approval')
        try:
            observation = fresh_tls(config)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            add('registered_tls_replay', 'unavailable', verification_id=verification['id'], detail=str(exc)[:300])
            continue
        expected = tls_outcomes(verification.get('observation', {}), fallback)
        actual = tls_outcomes(observation, fallback)
        add('registered_tls_replay', 'passed' if expected == actual and all(actual.values()) else 'failed',
            verification_id=verification['id'], expected=expected, actual=actual, observation=observation,
            identity='Fresh ephemeral RSA laboratory certificate; original certificate identity is NOT reproduced.',
            detail='Fresh authored loopback behavior only. Latencies and certificate fingerprints are intentionally not compared; no production assurance.')


def _replay(bundle, expected_digest, checks, tls_lab=False, isolated=False):
    def add(check, status, **details):
        checks.append({'check': check, 'status': status, **details})

    stored = bundle.pop('content_digest', None)
    actual = digest(bundle)
    add('canonical_bundle', 'passed' if stored == actual else 'failed')
    add('trusted_digest', 'not_checked' if expected_digest is None else 'passed' if expected_digest == actual else 'failed',
        detail='Only a digest obtained independently of this bundle authenticates its origin.')
    required = {'manifest', 'snapshots', 'findings', 'evidence', 'coverage', 'proposals', 'decisions', 'verifications', 'audit', 'audit_checkpoint', 'cbom'}
    if bundle.get('schema') != 'ecdat.bundle.v1' or not required <= bundle.keys():
        raise ValueError('Unsupported or incomplete bundle schema')
    for key in required - {'audit_checkpoint', 'cbom'}:
        if not isinstance(bundle[key], list):
            raise ValueError('Expected bundle list: ' + key)
    add('audit_chain', 'passed' if verify_audit(bundle['audit'], bundle['audit_checkpoint']) else 'failed')
    try:
        validate_cbom(bundle['cbom'])
        add('cbom_schema', 'passed')
    except Exception:
        add('cbom_schema', 'failed')
    cbom_ids = Counter(item.get('bom-ref') for item in bundle['cbom'].get('components', []))
    add('cbom_inventory', 'passed' if cbom_ids == Counter(item['id'] for item in bundle['findings']) else 'failed')
    if any(check['status'] == 'failed' for check in checks):
        return

    manifests, snapshots = {}, {}
    for record in bundle['manifest']:
        artifact_id = record['artifact_id']
        if artifact_id in manifests or digest(record['manifest']) != record['manifest_digest']:
            raise ValueError('Duplicate artifact or invalid manifest digest')
        manifests[artifact_id] = manifest_index(record['manifest'])
    for record in bundle['snapshots']:
        artifact_id = record['artifact_id']
        if artifact_id in snapshots or artifact_id not in manifests:
            raise ValueError('Duplicate or unbound snapshot')
        snapshots[artifact_id] = record
        original = next(item for item in bundle['manifest'] if item['artifact_id'] == artifact_id)
        if record['manifest_digest'] != original['manifest_digest'] or manifest_index(record['files']) != manifests[artifact_id]:
            raise ValueError('Snapshot differs from committed manifest')
    add('snapshot_manifest_binding', 'passed')
    for kind in ('findings', 'coverage'):
        if any(item.get('artifact_id') not in manifests or not item.get('scan_id') for item in bundle[kind]):
            raise ValueError('Unbound ' + kind + ' record')

    proposals = {item['id']: item for item in bundle['proposals']}
    if len(proposals) != len(bundle['proposals']):
        raise ValueError('Duplicate proposal')
    scans = {item['id']: item for item in bundle.get('scans', [])}
    for proposal in proposals.values():
        binding = proposal['binding']
        valid = digest(binding) == proposal['proposal_digest']
        valid &= all(proposal.get(key) == binding.get(key) for key in binding if key in proposal)
        valid &= proposal['artifact_id'] in manifests
        if proposal['artifact_id'] in manifests:
            original = next(item for item in bundle['manifest'] if item['artifact_id'] == proposal['artifact_id'])
            valid &= binding.get('manifest_digest') == original['manifest_digest']
        if 'after' in proposal:
            valid &= digest(proposal['after']) == binding.get('after_digest')
        add('proposal_binding', 'passed' if valid else 'failed', proposal_id=proposal['id'])
        baseline = scans.get(binding.get('baseline_scan_id'))
        add('baseline_binding', 'unavailable' if baseline is None else
            'passed' if baseline.get('artifact_id') == proposal['artifact_id'] and digest({key: baseline[key] for key in SCAN_FIELDS}) == binding.get('baseline_digest') else 'failed',
            proposal_id=proposal['id'])
    for decision in bundle['decisions']:
        proposal = proposals.get(decision['proposal_id'])
        valid = bool(proposal and decision['proposal_digest'] == proposal['proposal_digest'] and decision['reviewer_id'] != proposal['author_id'])
        add('decision_binding', 'passed' if valid else 'failed', decision_id=decision['id'],
            detail='Record identity separation only; signer enrollment requires independent passport verification.')
    if any(check['status'] == 'failed' for check in checks):
        return

    if not manifests:
        add('static_replay', 'unavailable', detail='No input artifacts were exported.')
    for artifact_id, entries in manifests.items():
        snapshot = snapshots.get(artifact_id)
        if snapshot is None:
            add('snapshot_bytes', 'unavailable', artifact_id=artifact_id, detail='Snapshot is absent.')
            continue
        with tempfile.TemporaryDirectory(prefix='ecdat-clean-replay-') as temporary:
            directory = Path(temporary) / 'input'
            directory.mkdir()
            unavailable = []
            for item in snapshot['files']:
                if item.get('availability') != 'included':
                    unavailable.append(item['path'])
                    continue
                if item.get('encoding') != 'base64' or not isinstance(item.get('content'), str) or len(item['content']) > 4 * ((item['size'] + 2) // 3):
                    raise ValueError('Invalid snapshot encoding or size')
                data = base64.b64decode(item['content'], validate=True)
                if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                    raise ValueError('Snapshot byte digest mismatch')
                target = directory.joinpath(*safe_path(item['path']).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            add('snapshot_bytes', 'unavailable' if unavailable else 'passed', artifact_id=artifact_id, unavailable_paths=unavailable)
            if unavailable:
                add('static_replay', 'unavailable', artifact_id=artifact_id, detail='Withheld or missing bytes prevent complete replay; no partial scan is promoted to success.')
                continue
            try:
                fresh = scan_restored(directory, isolated=isolated)
            except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
                add('static_replay', 'unavailable', artifact_id=artifact_id, detail=str(exc)[:300])
                continue
            if manifest_index(fresh['manifest']) != entries:
                add('restored_manifest', 'failed', artifact_id=artifact_id)
                continue
            add('restored_manifest', 'passed', artifact_id=artifact_id)
            recorded_coverage = [item for item in bundle['coverage'] if item['artifact_id'] == artifact_id]
            scan_ids = sorted({item['scan_id'] for item in recorded_coverage})
            if not scan_ids:
                add('static_replay', 'unavailable', artifact_id=artifact_id, detail='No recorded scan coverage to compare.')
            for scan_id in scan_ids:
                old_coverage = [item for item in recorded_coverage if item.get('scan_id') == scan_id]
                old_findings = [item for item in bundle['findings'] if item.get('scan_id') == scan_id and item['artifact_id'] == artifact_id]
                current_coverage = [item for item in fresh['coverage'] if isolated or item['adapter'] not in EXTERNAL_ADAPTERS]
                comparable = [item for item in old_coverage if isolated or item['adapter'] not in EXTERNAL_ADAPTERS]
                info = {'artifact_id': artifact_id, 'scan_id': scan_id}
                versions = {item.get('version') for item in comparable}
                current_versions = {item.get('version') for item in current_coverage}
                if versions != current_versions:
                    add('static_replay', 'unavailable', **info, detail='Scanner version differs; no reproducibility assertion.', recorded_versions=sorted(str(v) for v in versions), current_versions=sorted(str(v) for v in current_versions))
                    continue
                expected_coverage = normalized(comparable, COVERAGE_FIELDS)
                actual_coverage = normalized(current_coverage, COVERAGE_FIELDS)
                expected_findings = normalized(old_findings, FINDING_FIELDS)
                actual_findings = normalized(fresh['findings'], FINDING_FIELDS)
                old_evidence = [item for item in bundle['evidence'] if item.get('scan_id') == scan_id and item['artifact_id'] == artifact_id and (isolated or item.get('source') not in ('syft', 'syft-oci'))]
                current_evidence = [item for item in fresh['evidence'] if isolated or item.get('source') not in ('syft', 'syft-oci')]
                expected_evidence = normalized(old_evidence, EVIDENCE_FIELDS)
                actual_evidence = normalized(current_evidence, EVIDENCE_FIELDS)
                authorized_ids = {item['id'] for item in bundle['evidence'] if item.get('scan_id') == scan_id and item['artifact_id'] == artifact_id}
                citations_valid = all(set(item.get('evidence_ids', [])) <= authorized_ids for item in old_findings)
                def evidence_links(findings, evidence):
                    by_id = {item['id']: item for item in evidence}
                    return Counter(rfc8785.dumps({'finding': {key: item.get(key) for key in FINDING_FIELDS}, 'evidence': sorted(digest({key: by_id[eid].get(key) for key in EVIDENCE_FIELDS}) for eid in item.get('evidence_ids', []) if eid in by_id)}).decode() for item in findings)
                citations_valid &= evidence_links(old_findings, old_evidence) == evidence_links(fresh['findings'], current_evidence)
                matches = expected_coverage == actual_coverage and expected_findings == actual_findings and expected_evidence == actual_evidence and citations_valid
                add('static_replay', 'passed' if matches else 'failed', **info,
                    evidence=difference(expected_evidence, actual_evidence), citations_valid=citations_valid,
                    findings=difference(expected_findings, actual_findings), coverage=difference(expected_coverage, actual_coverage),
                    detail='Compared located observations and coverage including unsupported/partial/failed files; this does not prove runtime behavior.')
                external = [item for item in old_coverage if item['adapter'] in EXTERNAL_ADAPTERS and item['status'] not in ('unavailable', 'not_run', 'unsupported')]
                if external and not isolated:
                    add('isolated_adapter_replay', 'unavailable', **info, adapters=sorted({item['adapter'] for item in external}), detail='Syft requires its independently configured no-network sandbox; native replay never launches it.')
    if bundle['verifications']:
        if tls_lab and not any(check['status'] == 'failed' for check in checks):
            replay_tls(bundle, proposals, add)
        else:
            add('registered_tls_replay', 'unavailable', detail='Use --tls-lab to replay behavior with a fresh laboratory identity. The original private key is withheld; original identity is never reproduced.')
    add('chain_freshness', 'not_checked', detail='Use the independent passport verifier with pinned deployment and enrolled keys.')


def replay(bundle_path, expected_digest=None, tls_lab=False, isolated=False):
    checks = []
    try:
        path = Path(bundle_path)
        if path.stat().st_size > MAX_BUNDLE_BYTES:
            raise ValueError('Bundle size limit exceeded')
        bundle = strict_json(path.read_text(encoding='utf-8'))
        if not isinstance(bundle, dict):
            raise ValueError('Bundle must be an object')
        _replay(bundle, expected_digest, checks, tls_lab, isolated)
    except Exception as exc:
        checks.append({'check': 'bundle_structure_or_bytes', 'status': 'failed', 'detail': f'{type(exc).__name__}: {str(exc)[:300]}'})
    failed = any(item['status'] == 'failed' for item in checks)
    incomplete = any(item['status'] == 'unavailable' for item in checks)
    reproduced = any(item['check'] == 'static_replay' and item['status'] == 'passed' for item in checks)
    behavioral = any(item['check'] == 'registered_tls_replay' and item['status'] == 'passed' for item in checks)
    status = 'failed' if failed else 'partial' if incomplete else 'lab_reproduced' if reproduced and behavioral else 'static_reproduced' if reproduced else 'integrity_checked'
    return {'schema': 'ecdat.replay.v2', 'status': status,
            'authenticated': not failed and any(item['check'] == 'trusted_digest' and item['status'] == 'passed' for item in checks),
            'checks': checks,
            'limits': {'bundle_bytes': MAX_BUNDLE_BYTES, 'restored_bytes_per_artifact': MAX_RESTORED_BYTES, 'file_bytes': MAX_FILE_BYTES},
            'scope': 'Offline bytes and static observations; optional fresh-identity authored loopback TLS behavior. No AI, ECDAT server, original TLS identity, chain freshness, or production assurance.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle')
    parser.add_argument('--expected-digest', help='Canonical content digest from an independently trusted receipt')
    parser.add_argument('--output')
    parser.add_argument('--tls-lab', action='store_true', help='Run fixed loopback TLS harness with a fresh ephemeral laboratory identity')
    parser.add_argument('--isolated', action='store_true', help='Run the installed fixed no-network scanner container, including Syft')
    args = parser.parse_args()
    result = replay(args.bundle, args.expected_digest, args.tls_lab, args.isolated)
    content = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(content, encoding='utf-8')
    print(content)
    sys.exit(1 if result['status'] == 'failed' else 2 if result['status'] == 'partial' else 0)

