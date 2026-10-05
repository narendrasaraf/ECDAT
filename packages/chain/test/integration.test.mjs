import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {digest} from '../lib/bundle.mjs';
import {root} from '../scripts/compile.mjs';

test('API bridge persists local chain, verifies independently and detects signature downgrade',()=>{
  const folder=fs.mkdtempSync(path.join(os.tmpdir(),'ecdat-chain-test-'));
  const state=path.join(folder,'chain'),bundlePath=path.join(folder,'bundle.json');
  const binding={schema:'ecdat.proposal.v1',author_id:'analyst',policy:'local-evaluation',test:'authored-test'};
  const proposal={id:'p1',author_id:'analyst',binding,proposal_digest:digest(binding)};
  const bundle={schema:'ecdat.bundle.v1',project_id:'test-project',manifest:[],findings:[],evidence:[{id:'e1',value:'hybrid-exchange'}],coverage:[],proposals:[proposal],decisions:[{id:'d1',proposal_id:'p1',proposal_digest:proposal.proposal_digest,reviewer_id:'reviewer',action:'approve'}],verifications:[{id:'v1',proposal_id:'p1',status:'failed',reason:'authored failure still recorded honestly'}],audit:[],audit_checkpoint:{count:0,head:'0'.repeat(64)}};
  bundle.content_digest=digest(bundle);fs.writeFileSync(bundlePath,JSON.stringify(bundle));
  function run(script,args,expected=0){const result=spawnSync(process.execPath,[path.join(root,'scripts',script),...args],{encoding:'utf8',windowsHide:true,timeout:90000,maxBuffer:2*1024*1024});assert.equal(result.status,expected,result.stdout+'\n'+result.stderr);return JSON.parse(result.stdout.trim());}
  const anchor=run('api-anchor.mjs',[bundlePath,state]);assert.equal(anchor.status,'included-local');assert.equal(anchor.anchor.verification_status,'failed');assert.equal(anchor.signatures.length,2);
  const verifierArgs=[bundlePath,'--passport',anchor.passport_path,'--trust',anchor.trust_path,'--deployment',path.join(state,'deployment.json'),'--state-dir',state];
  const verified=run('verify-anchor.mjs',verifierArgs);assert.equal(verified.chain.status,'passed');assert.equal(verified.chain.finality,'local-development-no-independent-finality');
  // Simulate interruption after the result checkpoint but before the final passport rename.
  fs.unlinkSync(anchor.passport_path);
  const recovered=run('api-anchor.mjs',[bundlePath,state]);assert.equal(recovered.anchor.transaction_hash,anchor.anchor.transaction_hash);assert.equal(recovered.merkle_root,anchor.merkle_root);
  const repeated=run('api-anchor.mjs',[bundlePath,state]);assert.equal(repeated.idempotent,true);assert.equal(repeated.anchor.transaction_hash,anchor.anchor.transaction_hash);
  const passport=JSON.parse(fs.readFileSync(anchor.passport_path,'utf8'));passport.signatures=passport.signatures.filter(s=>s.algorithm!=='ml-dsa-65');const changed=path.join(folder,'downgraded.json');fs.writeFileSync(changed,JSON.stringify(passport));
  const invalid=run('bundle.mjs',['verify',bundlePath,'--passport',changed,'--trust',anchor.trust_path],1);assert.match(invalid.error,/Required signature missing/);
  for(const [field,value] of [['verification_status','passed'],['application_proposal_id','substituted-proposal'],['application_verification_id','substituted-verification'],['proposal_digest','0'.repeat(64)]]) {
    const relabelled=JSON.parse(fs.readFileSync(anchor.passport_path,'utf8'));relabelled.anchor[field]=value;
    const relabelledPath=path.join(folder,'relabelled-'+field+'.json');fs.writeFileSync(relabelledPath,JSON.stringify(relabelled));
    assert.match(run('bundle.mjs',['verify',bundlePath,'--passport',relabelledPath,'--trust',anchor.trust_path],1).error,/Anchor application result binding mismatch/);
  }
  const badBundle=structuredClone(bundle);badBundle.decisions[0].reviewer_id='analyst';delete badBundle.content_digest;badBundle.content_digest=digest(badBundle);const badPath=path.join(folder,'self.json');fs.writeFileSync(badPath,JSON.stringify(badBundle));
  assert.match(run('api-anchor.mjs',[badPath,state],1).error,/self-approval/);
  const alias=structuredClone(bundle);alias.proposals[0].author_id='substituted-author';delete alias.content_digest;alias.content_digest=digest(alias);const aliasPath=path.join(folder,'substituted-author.json');fs.writeFileSync(aliasPath,JSON.stringify(alias));
  assert.match(run('api-anchor.mjs',[aliasPath,state],1).error,/approved binding/);
});
