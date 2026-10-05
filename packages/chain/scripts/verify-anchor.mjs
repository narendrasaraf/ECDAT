import fs from 'node:fs';
import {JsonRpcProvider} from 'ethers';
import {parseStrict,verifyPassport} from '../lib/bundle.mjs';
import {openLocal} from '../lib/local-chain.mjs';
import {verifyAnchor} from '../lib/verify-anchor.mjs';
import {compile} from './compile.mjs';
const [bundlePath,...args]=process.argv.slice(2);
const flag=name=>{const i=args.indexOf(name);return i<0?undefined:args[i+1];};
const read=p=>parseStrict(fs.readFileSync(p,'utf8'));
let local,provider;
try {
  const bundle=read(bundlePath),passport=read(flag('--passport')),trust=read(flag('--trust'));
  const result=verifyPassport(bundle,passport,trust);
  const deployment=read(flag('--deployment'));
  if(flag('--state-dir')) {local=await openLocal(flag('--state-dir'),{existingOnly:true});provider=local.provider;}
  else {if(!flag('--rpc'))throw new Error('Provide --state-dir for local or --rpc for remote chain verification');provider=new JsonRpcProvider(flag('--rpc'));}
  result.chain=await verifyAnchor(passport,provider,deployment,compile().abi);result.chain_status='checked';
  console.log(JSON.stringify(result));
} catch(e){console.log(JSON.stringify({valid:false,error:e.message}));process.exitCode=1;}
finally {if(local)await local.close();else provider?.destroy();}
