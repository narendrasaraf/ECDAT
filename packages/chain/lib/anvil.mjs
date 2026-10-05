import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {randomInt} from 'node:crypto';
import {JsonRpcProvider,HDNodeWallet} from 'ethers';
import {root} from '../scripts/compile.mjs';

export const DEVELOPMENT_MNEMONIC='test test test test test test test test test test test junk';
export async function startAnvil({stateDir,port=randomInt(20000,50000)}={}) {
  const binary=process.env.ECDAT_ANVIL ?? path.resolve(root,'../../.ecdat/tools/foundry/anvil.exe');
  if(!fs.existsSync(binary))throw new Error('Anvil is unavailable; install verified native runtime or set ECDAT_ANVIL');
  const child=spawn(binary,['--silent','--host','127.0.0.1','--port',String(port),'--chain-id','31337','--hardfork','cancun','--mnemonic',DEVELOPMENT_MNEMONIC,'--accounts','6','--preserve-historical-states'],{windowsHide:true,stdio:['ignore','ignore','pipe']});
  let stderr='',spawnError;
  child.stderr.on('data',data=>{stderr=(stderr+data.toString()).slice(-4096);});child.on('error',e=>{spawnError=e;});
  const url=`http://127.0.0.1:${port}`;
  let ready=false;
  for(let i=0;i<100;i++) {
    if(spawnError || child.exitCode!==null) {child.kill();throw spawnError ?? new Error('Anvil exited: '+stderr);}
    try {const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_chainId',params:[]}),signal:AbortSignal.timeout(500)});const data=await response.json();if(data.result==='0x7a69'){ready=true;break;}}catch{}
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  if(!ready){child.kill();throw new Error('Anvil loopback RPC did not become ready: '+stderr);}
  const provider=new JsonRpcProvider(url,31337,{staticNetwork:true,cacheTimeout:-1});provider.pollingInterval=50;
  const stateFile=stateDir?path.join(stateDir,'anvil-state.json'):undefined;
  if(stateFile && fs.existsSync(stateFile)) {
    try {await provider.send('anvil_loadState',[JSON.parse(fs.readFileSync(stateFile,'utf8')).state]);}
    catch(error){provider.destroy();child.kill();throw new Error('Local chain snapshot cannot load: '+error.message);}
  }
  const wallets=Array.from({length:6},(_,i)=>HDNodeWallet.fromPhrase(DEVELOPMENT_MNEMONIC,undefined,`m/44'/60'/0'/0/${i}`));
  async function checkpoint() {
    if(stateFile) {
      const state=await provider.send('anvil_dumpState',[true]);
      fs.writeFileSync(stateFile+'.tmp',JSON.stringify({schema:'ecdat.anvil.snapshot.v1',state}));fs.renameSync(stateFile+'.tmp',stateFile);
    }
  }
  async function close() {
    try {await checkpoint();}finally {provider.destroy();const ended=new Promise(resolve=>child.once('exit',resolve));child.kill();if(child.exitCode===null)await Promise.race([ended,new Promise(resolve=>setTimeout(resolve,2000))]);}
  }
  return {provider,child,wallets,url,checkpoint,close};
}
