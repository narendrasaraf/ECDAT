import {createHash,randomBytes,generateKeyPairSync,createPrivateKey,createPublicKey,sign,verify} from 'node:crypto';
import canonicalize from 'canonicalize';
import {StandardMerkleTree} from '@openzeppelin/merkle-tree';

export const TYPES=['string','string','bytes32','bytes32'];
export function canonical(value) {
  function validate(v) {
    if (typeof v==='number' && (!Number.isFinite(v) || (Number.isInteger(v) && !Number.isSafeInteger(v)))) throw new Error('Non-I-JSON number');
    if (typeof v==='string' && /[\uD800-\uDFFF]/u.test(v.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/gu,''))) throw new Error('Invalid Unicode');
    if (Array.isArray(v)) v.forEach(validate);
    else if (v && typeof v==='object') Object.entries(v).forEach(([k,x])=>{validate(k);validate(x);});
    else if (v !== null && !['number','string','boolean'].includes(typeof v)) throw new Error('Unsupported JSON value');
  }
  validate(value);
  return canonicalize(value);
}
export const digest=value=>createHash('sha256').update(canonical(value)).digest('hex');
export const bytesDigest=value=>createHash('sha256').update(value).digest('hex');

// Reject duplicate JSON object keys before JSON.parse can erase their ambiguity.
export function parseStrict(text) {
  let i=0;
  const ws=()=>{while (/\s/u.test(text[i] ?? '') && i<text.length) i++;};
  function string() {
    const start=i++;
    while(i<text.length) {if(text[i]==='\\'){i+=2;continue;} if(text[i++]==='"')return JSON.parse(text.slice(start,i));}
    throw new Error('Unterminated JSON string');
  }
  function value() {
    ws();
    if(text[i]==='"'){string();return;}
    if(text[i]==='{') {
      i++;ws(); const keys=new Set();
      if(text[i]==='}'){i++;return;}
      while(true){ws();if(text[i]!=='"')throw new Error('Expected JSON key'); const key=string(); if(keys.has(key))throw new Error('Duplicate JSON key: '+key);keys.add(key);ws();if(text[i++]!==':')throw new Error('Expected colon');value();ws();if(text[i]==='}'){i++;return;}if(text[i++]!==',')throw new Error('Expected comma');}
    }
    if(text[i]==='['){i++;ws();if(text[i]===']'){i++;return;}while(true){value();ws();if(text[i]===']'){i++;return;}if(text[i++]!==',')throw new Error('Expected comma');}}
    const token=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(text.slice(i));
    if(!token)throw new Error('Invalid JSON token');i+=token[0].length;
  }
  value();ws();if(i!==text.length)throw new Error('Trailing JSON content');
  const parsed=JSON.parse(text);canonical(parsed);return parsed;
}

export function checkBundle(bundle) {
  if(bundle.schema!=='ecdat.bundle.v1' || typeof bundle.project_id!=='string')throw new Error('Unsupported bundle schema or project');
  const {content_digest,...payload}=bundle;
  if(!/^[a-f0-9]{64}$/u.test(content_digest) || digest(payload)!==content_digest)throw new Error('Bundle content digest mismatch');
  for(const key of ['manifest','findings','evidence','coverage','proposals','decisions','verifications','audit']) if(!Array.isArray(bundle[key]))throw new Error('Missing bundle array: '+key);
  if(!bundle.audit_checkpoint || typeof bundle.audit_checkpoint!=='object')throw new Error('Missing audit checkpoint');
  return payload;
}

// The passport is a presentation envelope; these labels must come from committed
// application records, never from an editable claim adjacent to a valid root.
export function approvedVerification(bundle) {
  const completed=bundle.verifications.find(v=>['passed','failed','blocked','inconclusive'].includes(v.status) && v.proposal_id && bundle.proposals.some(p=>p.id===v.proposal_id));
  if(!completed)throw new Error('No completed verification with an exported proposal');
  const proposal=bundle.proposals.find(p=>p.id===completed.proposal_id);
  const decision=bundle.decisions.find(d=>d.proposal_id===proposal.id && d.action==='approve');
  if(!decision || decision.proposal_digest!==proposal.proposal_digest || digest(proposal.binding)!==proposal.proposal_digest)throw new Error('Missing or stale application approval');
  if(proposal.author_id!==proposal.binding.author_id)throw new Error('Application proposer identity does not match approved binding');
  if(!decision.reviewer_id || !proposal.author_id || decision.reviewer_id===proposal.author_id)throw new Error('Application reviewer identity missing or self-approval rejected');
  return {completed,proposal,decision};
}

export function recordValues(bundle) {
  const payload=checkBundle(bundle);
  return Object.keys(payload).sort().flatMap(type=>Array.isArray(payload[type]) && payload[type].length ? payload[type].map((value,index)=>({key:`${type}/${index}`,type,index,value})):[{key:type,type,index:null,value:payload[type]}]);
}
export function signaturePayload(passport) {
  return {schema:'ecdat.passport.signature.v1',project_id:passport.project_id,bundle_digest:passport.bundle_digest,merkle_root:passport.merkle_root,record_count:passport.record_count};
}
export function seal(bundle) {
  const records=recordValues(bundle).map(r=>({key:r.key,type:r.type,index:r.index,digest:digest(r.value),salt:randomBytes(32).toString('hex')}));
  const values=records.map(r=>[bundle.project_id,r.key,'0x'+r.digest,'0x'+r.salt]);
  const tree=StandardMerkleTree.of(values,TYPES);
  for(let i=0;i<records.length;i++)records[i].proof=tree.getProof(i);
  return {schema:'ecdat.passport.v1',project_id:bundle.project_id,bundle_digest:bundle.content_digest,merkle_root:tree.root,record_count:records.length,records,signatures:[],anchor:null};
}
export function generateEnrollment(keyId,algorithm='ed25519') {
  if(!['ed25519','ml-dsa-65'].includes(algorithm))throw new Error('Unsupported signature algorithm');
  const pair=generateKeyPairSync(algorithm);
  return {private_key_pem:pair.privateKey.export({type:'pkcs8',format:'pem'}),enrollment:{key_id:keyId,algorithm,public_key_pem:pair.publicKey.export({type:'spki',format:'pem'}),revoked:false}};
}
export function signPassport(passport,keyId,algorithm,privatePem) {
  if(typeof keyId!=='string' || !keyId)throw new Error('Signer key ID required');
  const key=createPrivateKey(privatePem);
  if(key.asymmetricKeyType!==algorithm)throw new Error('Private-key algorithm mismatch');
  const signature=sign(null,Buffer.from(canonical(signaturePayload(passport))),key).toString('base64');
  return {...passport,signatures:[...passport.signatures,{key_id:keyId,algorithm,signature}]};
}
export function verifyPassport(bundle,passport,trust) {
  checkBundle(bundle);
  if(passport.schema!=='ecdat.passport.v1' || passport.project_id!==bundle.project_id || passport.bundle_digest!==bundle.content_digest)throw new Error('Passport scope mismatch');
  if(passport.anchor) {
    const {completed,proposal}=approvedVerification(bundle);
    if(passport.anchor.application_proposal_id!==proposal.id || passport.anchor.proposal_digest!==proposal.proposal_digest || passport.anchor.verification_status!==completed.status || (passport.anchor.application_verification_id!==undefined && passport.anchor.application_verification_id!==completed.id))throw new Error('Anchor application result binding mismatch');
  }
  const expected=recordValues(bundle);
  if(passport.record_count!==expected.length || passport.records.length!==expected.length)throw new Error('Record count mismatch');
  const byKey=new Map(passport.records.map(r=>[r.key,r]));
  if(byKey.size!==expected.length)throw new Error('Duplicate passport record');
  const leaves=[];
  for(const e of expected) {
    const r=byKey.get(e.key);
    if(!r || r.digest!==digest(e.value) || r.type!==e.type || r.index!==e.index || !/^[a-f0-9]{64}$/u.test(r.salt))throw new Error('Record digest or identity mismatch: '+e.key);
    const leaf=[bundle.project_id,r.key,'0x'+r.digest,'0x'+r.salt];leaves.push(leaf);
    if(!StandardMerkleTree.verify(passport.merkle_root,TYPES,leaf,r.proof))throw new Error('Merkle inclusion mismatch');
  }
  if(StandardMerkleTree.of(leaves,TYPES).root!==passport.merkle_root)throw new Error('Full Merkle root mismatch');
  const signatures=[];
  if(!Array.isArray(passport.signatures))throw new Error('Missing signatures array');
  if(trust && passport.signatures.length===0)throw new Error('Trusted signature required');
  const seenSigners=new Set();
  for(const s of passport.signatures) {
    if(seenSigners.has(s.key_id))throw new Error('Duplicate signer');seenSigners.add(s.key_id);
    const enrolled=trust?.keys?.find(k=>k.key_id===s.key_id);
    if(!enrolled || enrolled.revoked || enrolled.algorithm!==s.algorithm)throw new Error('Signer not trusted, revoked or algorithm mismatch: '+s.key_id);
    const key=createPublicKey(enrolled.public_key_pem);
    if(key.asymmetricKeyType!==s.algorithm)throw new Error('Enrolled-key algorithm mismatch');
    if(!verify(null,Buffer.from(canonical(signaturePayload(passport))),key,Buffer.from(s.signature,'base64')))throw new Error('Passport signature mismatch');
    signatures.push({key_id:s.key_id,algorithm:s.algorithm,status:'passed'});
  }
  for(const required of trust?.required_key_ids ?? [])if(!seenSigners.has(required))throw new Error('Required signature missing: '+required);
  return {valid:true,integrity:'passed',merkle_inclusion:'passed',signatures,signature_status:signatures.length?'passed':'unsigned',chain_status:'not_checked',scanner_truth:'not_established_by_commitment',bundle_digest:bundle.content_digest,merkle_root:passport.merkle_root};
}
export function disclose(bundle,passport,key) {
  const e=recordValues(bundle).find(r=>r.key===key);
  const record=passport.records.find(r=>r.key===key);
  if(!e || !record)throw new Error('Unknown disclosure key');
  return {schema:'ecdat.disclosure.v1',project_id:bundle.project_id,merkle_root:passport.merkle_root,record,value:e.value};
}
export function verifyDisclosure(disclosure,expectedRoot) {
  if(!expectedRoot || disclosure.merkle_root!==expectedRoot)throw new Error('A separately trusted Merkle root is required');
  const r=disclosure.record;
  if(digest(disclosure.value)!==r.digest || !StandardMerkleTree.verify(expectedRoot,TYPES,[disclosure.project_id,r.key,'0x'+r.digest,'0x'+r.salt],r.proof))throw new Error('Disclosure proof invalid');
  return {valid:true,membership:'passed',completeness:'not_established'};
}
