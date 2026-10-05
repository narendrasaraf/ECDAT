"""Execute real no-network discovery of authored directory/OCI and an actual ELF."""
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
folder=ROOT/'.ecdat/acceptance/adapters'
folder.mkdir(parents=True,exist_ok=True)

def tar_bytes(files):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as archive:
        for name,data in files.items():
            entry=tarfile.TarInfo(name);entry.size=len(data);entry.mtime=0;entry.mode=0o644
            archive.addfile(entry,io.BytesIO(data))
    return stream.getvalue()

def blob(value):
    return json.dumps(value,separators=(',',':')).encode()

package={'name':'ecdat-authored-oci-fixture','version':'1.0.0','license':'MIT','description':'Authored inventory fixture; no application code is executed'}
(folder/'package.json').write_bytes(blob(package))
layer=tar_bytes({'app/package.json':blob(package),'etc/os-release':b'ID=debian\nVERSION_ID=12\nPRETTY_NAME="ECDAT authored fixture"\n'})
layer_hash=hashlib.sha256(layer).hexdigest()
config=blob({'architecture':'amd64','os':'linux','rootfs':{'type':'layers','diff_ids':['sha256:'+layer_hash]},'config':{}})
config_hash=hashlib.sha256(config).hexdigest()
manifest=blob({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':'sha256:'+config_hash,'size':len(config)},'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar','digest':'sha256:'+layer_hash,'size':len(layer)}]})
manifest_hash=hashlib.sha256(manifest).hexdigest()
index=blob({'schemaVersion':2,'manifests':[{'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':'sha256:'+manifest_hash,'size':len(manifest),'annotations':{'org.opencontainers.image.ref.name':'ecdat-authored:1'}}]})
(folder/'authored.oci.tar').write_bytes(tar_bytes({'oci-layout':b'{"imageLayoutVersion":"1.0.0"}','index.json':index,'blobs/sha256/'+config_hash:config,'blobs/sha256/'+manifest_hash:manifest,'blobs/sha256/'+layer_hash:layer}))
# Retrieve installed OpenSSL library bytes without executing the library.
container=subprocess.check_output(['docker','create','ecdat-scanner:local'],text=True).strip()
try:
    subprocess.run(['docker','cp',container+':/usr/lib/x86_64-linux-gnu/libcrypto.so.3',str(folder/'libcrypto.so.3')],check=True,capture_output=True)
finally:
    subprocess.run(['docker','rm',container],check=True,capture_output=True)
command=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--cpus','1','--pids-limit','96','--tmpfs','/tmp:rw,noexec,nosuid,size=128m','--user','65532:65532','--mount',f'type=bind,source={folder},target=/input,readonly','ecdat-scanner:local']
result=subprocess.run(command,capture_output=True,text=True,timeout=150)
if result.returncode:raise RuntimeError(result.stderr)
scan=json.loads(result.stdout)
(folder.parent/'isolated-adapters.json').write_text(json.dumps(scan,indent=2),encoding='utf-8')
coverage=scan['coverage']
assert any(c['adapter']=='syft_inventory' and c['status']=='complete' for c in coverage),coverage
assert any(c['adapter']=='syft_oci_inventory' and c['status']=='complete' for c in coverage),coverage
assert any(c['adapter']=='elf_symbols' and c['status']=='partial' for c in coverage),coverage
assert any(e.get('source')=='syft-oci' for e in scan['evidence']),scan['evidence']
assert any(f['claim']['kind']=='symbol_presence' for f in scan['findings']),scan['findings']
print(json.dumps({'status':'passed','coverage':coverage,'findings':len(scan['findings']),'package_evidence':sum(e['kind']=='package_presence' for e in scan['evidence']),'isolation':{'network':'none','input':'read-only','capabilities':'none','user':'65532','memory':'512m'}}))
