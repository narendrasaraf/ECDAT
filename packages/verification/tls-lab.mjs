import tls from 'node:tls';
import {readFileSync} from 'node:fs';
import {performance} from 'node:perf_hooks';

// This is a fixed authored loopback harness. Uploaded source is never executed.
const [configPath, keyPath, certPath] = process.argv.slice(2);
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const groups = config.tls.groups;
const permitted = new Set(['X25519', 'X25519MLKEM768']);
if (!Array.isArray(groups) || !groups.length || groups.some(g => !permitted.has(g))) throw new Error('Unsupported registered group');
const key = readFileSync(keyPath), cert = readFileSync(certPath);
const timeout = setTimeout(() => {process.stderr.write('TLS harness timeout');process.exit(2)}, 25000);
const server = tls.createServer({key, cert, minVersion:'TLSv1.3', maxVersion:'TLSv1.3', ecdhCurve:groups.join(':')}, socket => {
  socket.on('error', () => {});
  socket.on('data', data => socket.end(data));
});
server.on('tlsClientError', () => {});
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});
const port=server.address().port;
async function connect(clientGroups) {
  const started=performance.now();
  return new Promise(resolve => {
    let settled=false, negotiated={};
    const finish=result=>{if(settled)return;settled=true;socket.destroy();resolve({...result,elapsed_ms:performance.now()-started})};
    const socket=tls.connect({host:'127.0.0.1',port,servername:'localhost',ca:cert,rejectUnauthorized:true,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ecdhCurve:clientGroups.join(':')});
    socket.setTimeout(3000,()=>finish({connected:false,error:'timeout'}));
    socket.on('error',err=>finish({connected:false,error:err.code || err.message}));
    socket.once('secureConnect',()=>{
      negotiated={group:socket.getEphemeralKeyInfo()?.name,protocol:socket.getProtocol(),authorized:socket.authorized,cipher:socket.getCipher().standardName,authentication:'RSA',certificate_fingerprint:socket.getPeerCertificate().fingerprint256};
      socket.write('ECDAT authenticated payload');
    });
    socket.once('data',data=>finish({connected:true,...negotiated,payload_ok:data.toString()==='ECDAT authenticated payload'}));
  });
}
const hybrid=[];
for(let i=0;i<8;i++) hybrid.push(await connect(['X25519MLKEM768']));
const classical=await connect(['X25519']);
await new Promise(resolve=>server.close(resolve));
clearTimeout(timeout);
const times=hybrid.filter(x=>x.connected).map(x=>x.elapsed_ms).sort((a,b)=>a-b);
process.stdout.write(JSON.stringify({schema:'ecdat.tls-observation.v1',observed_at:new Date().toISOString(),target:'lab-tls-01',runtime:process.version,openssl:process.versions.openssl,configured_groups:groups,hybrid,classical,statistics:{attempts:8,successes:times.length,median_ms:times.length?times[Math.floor(times.length/2)]:null,p95_ms:times.length?times[Math.ceil(times.length*.95)-1]:null},limitations:['Authored loopback peer only','RSA certificate authentication remains','Latency is local and not an enterprise performance claim']}));
