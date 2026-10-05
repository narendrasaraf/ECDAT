import {Contract,keccak256,verifyTypedData} from 'ethers';
import {DECISION_TYPES} from './local-chain.mjs';

export async function verifyAnchor(passport,provider,deployment,abi) {
  const a=passport.anchor;
  if(!a)throw new Error('Passport has no anchor');
  const network=await provider.getNetwork();
  if(Number(network.chainId)!==deployment.chain_id || a.chain_id!==deployment.chain_id || a.contract.toLowerCase()!==deployment.address.toLowerCase() || a.code_hash!==deployment.code_hash)throw new Error('Network or independently pinned contract mismatch');
  if(keccak256(await provider.getCode(a.contract))!==deployment.code_hash)throw new Error('Deployed code identity mismatch');
  const c=new Contract(a.contract,abi,provider);
  const record=await c.proposals(a.proposal_id,a.proposal_version);
  if(record.state!==5n || record.resultRoot!==passport.merkle_root || record.resultDigest!=='0x'+passport.bundle_digest || record.digest!=='0x'+a.proposal_digest)throw new Error('On-chain commitment mismatch');
  if(record.proposer===record.reviewer || record.proposer===record.verifier || record.reviewer===record.verifier)throw new Error('On-chain separation of duties failed');
  const m=a.approval_message;
  if(!m || m.proposalId!==a.proposal_id || BigInt(m.version)!==BigInt(a.proposal_version) || m.proposalDigest!==record.digest || !m.approve || m.reviewer!==record.reviewer)throw new Error('Approval scope mismatch');
  const signer=verifyTypedData({name:'ECDAT EvidenceNotary',version:'1',chainId:a.chain_id,verifyingContract:a.contract},DECISION_TYPES,m,a.approval_signature);
  if(signer!==record.reviewer)throw new Error('Approval signature mismatch');
  const receipt=await provider.getTransactionReceipt(a.transaction_hash);
  const block=await provider.getBlock(a.block_number);
  if(!receipt || receipt.status!==1 || receipt.blockHash!==a.block_hash || !block || block.hash!==a.block_hash || receipt.blockNumber!==a.block_number)throw new Error('Anchor receipt absent or reorged');
  const matched=receipt.logs.some(log=>{
    if(log.address.toLowerCase()!==a.contract.toLowerCase())return false;
    try {const event=c.interface.parseLog(log);return event.name==='ResultRecorded' && event.args.id===a.proposal_id && event.args.version===BigInt(a.proposal_version) && event.args.resultRoot===passport.merkle_root && event.args.resultDigest==='0x'+passport.bundle_digest;}catch{return false;}
  });
  if(!matched)throw new Error('Result event missing from specified receipt');
  let finality='unknown';
  if(deployment.network==='local-development')finality='local-development-no-independent-finality';
  else {const finalized=await provider.getBlock('finalized');finality=finalized && finalized.number>=receipt.blockNumber?'finalized':'included-not-finalized';}
  return {status:'passed',chain_id:a.chain_id,contract:a.contract,record:'result-recorded',receipt:'included',finality,proposal_binding:'passed',reviewer_signature:'passed',rpc_trust:'provider-trusted-not-a-consensus-light-client'};
}
