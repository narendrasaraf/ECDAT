import fs from 'node:fs';
import {checkBundle,parseStrict,seal,verifyPassport,generateEnrollment,signPassport,disclose,verifyDisclosure} from '../lib/bundle.mjs';
const [command,input,...args]=process.argv.slice(2);
const flag=name=>{const i=args.indexOf(name);return i<0?undefined:args[i+1];};
function read(file){if(!file)throw new Error('Required file path missing');if(fs.statSync(file).size>64*1024*1024)throw new Error('JSON file exceeds 64 MiB');return parseStrict(fs.readFileSync(file,'utf8'));}
function emit(value){console.log(JSON.stringify(value));}
try {
  if(command==='seal'){
    let passport=seal(read(input));
    if(flag('--private'))passport=signPassport(passport,flag('--key-id'),flag('--algorithm')??'ed25519',fs.readFileSync(flag('--private'),'utf8'));
    if(flag('--out'))fs.writeFileSync(flag('--out'),JSON.stringify(passport,null,2));emit(passport);
  } else if(command==='verify') {
    emit(verifyPassport(read(input),read(flag('--passport')),flag('--trust')?read(flag('--trust')):undefined));
  } else if(command==='integrity') {
    checkBundle(read(input));emit({valid:true,integrity:'passed',authentication:'not_checked'});
  } else if(command==='keygen') {
    const algorithm=flag('--algorithm')??'ed25519'; const pair=generateEnrollment(input,algorithm);
    if(!flag('--private')||!flag('--trust'))throw new Error('keygen requires --private and --trust paths');
    fs.writeFileSync(flag('--private'),pair.private_key_pem,{flag:'wx',mode:0o600});
    fs.writeFileSync(flag('--trust'),JSON.stringify({schema:'ecdat.trust.v1',keys:[pair.enrollment]},null,2),{flag:'wx'});
    emit({created:true,key_id:input,algorithm,private_key_path:flag('--private'),trust_path:flag('--trust')});
  } else if(command==='disclose') {
    emit(disclose(read(input),read(flag('--passport')),flag('--key')));
  } else if(command==='verify-disclosure') {
    emit(verifyDisclosure(read(input),flag('--root')));
  } else throw new Error('Usage: bundle.mjs seal|verify|integrity|keygen|disclose|verify-disclosure FILE [flags]');
} catch(error) {emit({valid:false,error:error.message});process.exitCode=1;}
