import test from 'node:test';
import assert from 'node:assert/strict';
import {digest,parseStrict,seal,verifyPassport,generateEnrollment,signPassport,disclose,verifyDisclosure} from '../lib/bundle.mjs';
function fixture() {const b={schema:'ecdat.bundle.v1',project_id:'project-demo',manifest:[],findings:[],evidence:[{id:'e1',algorithm:'X25519MLKEM768'}],coverage:[],proposals:[],decisions:[],verifications:[],audit:[],audit_checkpoint:{count:0,head:'0'.repeat(64)}};return {...b,content_digest:digest(b)};}
test('RFC8785-compatible canonical digest and strict JSON boundaries',()=>{
  assert.equal(digest({b:1,a:2}),digest({a:2,b:1}));assert.deepEqual(parseStrict('{"a":[1,true,null,"text"]}'),{a:[1,true,null,'text']});
  assert.throws(()=>parseStrict('{"a":1,"a":2}'));assert.throws(()=>parseStrict('{"a":1,"\\u0061":2}'));assert.throws(()=>parseStrict('{"a":1e999}'));assert.throws(()=>parseStrict('{"a":"\\ud800"}'));assert.throws(()=>parseStrict('{"a":9007199254740992}'));
});
test('Merkle passport and selective disclosure detect tampering/omissions',()=>{
  const b=fixture(),p=seal(b);assert.equal(verifyPassport(b,p).integrity,'passed');assert.equal(verifyPassport(b,p).signature_status,'unsigned');
  const d=disclose(b,p,'evidence/0');assert.equal(verifyDisclosure(d,p.merkle_root).valid,true);assert.throws(()=>verifyDisclosure(d));
  const changed=structuredClone(b);changed.evidence[0].algorithm='RSA';assert.throws(()=>verifyPassport(changed,p));
  const proof=structuredClone(p);proof.records[0].proof[0]='0x'+'00'.repeat(32);assert.throws(()=>verifyPassport(b,proof));
  const missing=structuredClone(p);missing.records.pop();assert.throws(()=>verifyPassport(b,missing));
  const altered=structuredClone(d);altered.value.algorithm='RSA';assert.throws(()=>verifyDisclosure(altered,p.merkle_root));
});
test('Ed25519 signature requires externally enrolled unrevoked key',()=>{
  const b=fixture(),keys=generateEnrollment('reviewed-key');const p=signPassport(seal(b),'reviewed-key','ed25519',keys.private_key_pem),trust={keys:[keys.enrollment]};
  assert.equal(verifyPassport(b,p,trust).signature_status,'passed');assert.throws(()=>verifyPassport(b,p));
  assert.throws(()=>verifyPassport(b,p,{keys:[{...keys.enrollment,revoked:true}]}));
  const wrong=generateEnrollment('reviewed-key');assert.throws(()=>verifyPassport(b,p,{keys:[wrong.enrollment]}));
  const altered=structuredClone(p);altered.signatures[0].signature=Buffer.alloc(64).toString('base64');assert.throws(()=>verifyPassport(b,altered,trust));
});
test('ML-DSA-65 detached signature uses actual runtime implementation',t=>{
  let keys;try{keys=generateEnrollment('pq-key','ml-dsa-65');}catch(e){t.skip('Runtime lacks ML-DSA: run bundled Node24');return;}
  const b=fixture(),p=signPassport(seal(b),'pq-key','ml-dsa-65',keys.private_key_pem);assert.equal(verifyPassport(b,p,{keys:[keys.enrollment]}).signatures[0].algorithm,'ml-dsa-65');
});
