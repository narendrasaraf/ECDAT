import fs from 'node:fs';
import path from 'node:path';
import {id} from 'ethers';
import {parseStrict,seal,checkBundle,approvedVerification,generateEnrollment,signPassport,verifyPassport} from '../lib/bundle.mjs';
import {openLocal,signDecision} from '../lib/local-chain.mjs';
import {verifyAnchor} from '../lib/verify-anchor.mjs';

const [bundlePath,statePath]=process.argv.slice(2);
let local;
try {
  if(!bundlePath || !statePath)throw new Error('Usage: api-anchor.mjs BUNDLE_JSON STATE_DIRECTORY');
  if(fs.statSync(bundlePath).size>64*1024*1024)throw new Error('Bundle exceeds 64 MiB');
  const bundle=parseStrict(fs.readFileSync(bundlePath,'utf8'));checkBundle(bundle);
  const {completed,proposal}=approvedVerification(bundle);
  const stateDir=path.resolve(statePath);
  local=await openLocal(stateDir);
  const trustPath=path.join(stateDir,'trust.json');
  let trust=fs.existsSync(trustPath)?parseStrict(fs.readFileSync(trustPath,'utf8')):{schema:'ecdat.trust.v1',keys:[]};
  const algorithms=['ed25519','ml-dsa-65'];
  trust.required_key_ids=algorithms.map(algorithm=>'local-demo-'+algorithm);
  for(const algorithm of algorithms) {
    const keyId='local-demo-'+algorithm;
    if(!trust.keys.some(k=>k.key_id===keyId)) {
      const pair=generateEnrollment(keyId,algorithm);
      fs.writeFileSync(path.join(stateDir,keyId+'.pem'),pair.private_key_pem,{flag:'wx',mode:0o600});trust.keys.push(pair.enrollment);
      fs.writeFileSync(trustPath,JSON.stringify(trust,null,2));
    }
  }
  fs.writeFileSync(trustPath,JSON.stringify(trust,null,2));
  const passports=path.join(stateDir,'passports');fs.mkdirSync(passports,{recursive:true});
  const outputPath=path.join(passports,bundle.content_digest+'.json');
  if(fs.existsSync(outputPath)) {
    const existing=parseStrict(fs.readFileSync(outputPath,'utf8'));
    verifyPassport(bundle,existing,trust);
    await verifyAnchor(existing,local.provider,local.deployment,local.contract.interface.fragments);
    console.log(JSON.stringify({...existing,status:'included-local',passport_path:outputPath,trust_path:trustPath,idempotent:true}));
  } else {
    const journalPath=outputPath+'.pending';
    let journal=fs.existsSync(journalPath)?parseStrict(fs.readFileSync(journalPath,'utf8')):null;
    let passport=journal?.passport ?? seal(bundle);
    if(!journal)for(const algorithm of algorithms)passport=signPassport(passport,'local-demo-'+algorithm,algorithm,fs.readFileSync(path.join(stateDir,'local-demo-'+algorithm+'.pem'),'utf8'));
    verifyPassport(bundle,passport,trust);
    const proposalId=id('ecdat.local.passport:'+bundle.project_id+':'+bundle.content_digest);
    const version=1n;
    const block=await local.provider.getBlock('latest');const expiry=BigInt(journal?.expiry ?? block.timestamp+86400);
    journal ??= {schema:'ecdat.anchor.journal.v1',passport,expiry:expiry.toString()};
    const save=()=>{fs.writeFileSync(journalPath+'.tmp',JSON.stringify(journal));fs.renameSync(journalPath+'.tmp',journalPath);};save();
    let record=await local.contract.proposals(proposalId,version);
    if(record.state===0n){await(await local.contract.connect(local.signers[1]).propose(proposalId,version,'0x'+proposal.proposal_digest,expiry)).wait();await local.checkpoint();}
    record=await local.contract.proposals(proposalId,version);
    if(record.digest!=='0x'+proposal.proposal_digest)throw new Error('Pending chain proposal digest mismatch');
    let message=journal.approval_message,signature=journal.approval_signature;
    if(record.state===1n) {
      const nonce=await local.contract.nonces(local.addresses[2]);
      message={proposalId,version:version.toString(),proposalDigest:'0x'+proposal.proposal_digest,approve:true,reviewer:local.addresses[2],nonce:nonce.toString(),deadline:expiry.toString()};
      signature=await signDecision(local.contract,local.signingWallets[2],message);
      journal.approval_message=message;journal.approval_signature=signature;save();
      await(await local.contract.decide(proposalId,version,message.proposalDigest,true,message.reviewer,nonce,expiry,signature)).wait();await local.checkpoint();
    }
    record=await local.contract.proposals(proposalId,version);
    if(record.state===2n){await(await local.contract.connect(local.signers[3]).recordResult(proposalId,version,passport.merkle_root,'0x'+bundle.content_digest)).wait();await local.checkpoint();}
    record=await local.contract.proposals(proposalId,version);
    if(record.state!==5n || record.resultRoot!==passport.merkle_root || record.resultDigest!=='0x'+bundle.content_digest)throw new Error('Pending result state mismatch');
    async function receiptFor(eventName) {
      const events=await local.contract.queryFilter(local.contract.filters[eventName](proposalId,version),0,'latest');
      if(events.length!==1)throw new Error('Expected one '+eventName+' event');return local.provider.getTransactionReceipt(events[0].transactionHash);
    }
    const proposalReceipt=await receiptFor('ProposalRecorded'),approvalReceipt=await receiptFor('DecisionRecorded'),resultReceipt=await receiptFor('ResultRecorded');
    passport.anchor={network:'local-development',chain_id:31337,contract:local.deployment.address,code_hash:local.deployment.code_hash,proposal_id:proposalId,proposal_version:1,proposal_digest:proposal.proposal_digest,application_proposal_id:proposal.id,application_verification_id:completed.id,verification_status:completed.status,transaction_hash:resultReceipt.hash,block_number:resultReceipt.blockNumber,block_hash:resultReceipt.blockHash,proposal_transaction:proposalReceipt.hash,approval_transaction:approvalReceipt.hash,state:'included-local',finality:'not_independent_consensus',role_model:'local demo keys mirror authenticated application decision; not separate organizations',approval_signature:signature,approval_message:Object.fromEntries(Object.entries(message).map(([k,v])=>[k,typeof v==='bigint'?v.toString():v]))};
    const verification=verifyPassport(bundle,passport,trust);
    await verifyAnchor(passport,local.provider,local.deployment,local.contract.interface.fragments);
    fs.writeFileSync(outputPath,JSON.stringify(passport,null,2));
    console.log(JSON.stringify({...passport,status:'included-local',passport_path:outputPath,trust_path:trustPath,verification}));
  }
} catch(error) {console.log(JSON.stringify({status:'failed',error:error.message}));process.exitCode=1;}
finally {if(local)await local.close();}
