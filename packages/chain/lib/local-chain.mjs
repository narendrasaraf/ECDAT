import fs from 'node:fs';
import path from 'node:path';
import {Contract,ContractFactory,keccak256} from 'ethers';
import {compile} from '../scripts/compile.mjs';
import {startAnvil} from './anvil.mjs';

export const DECISION_TYPES={Decision:[{name:'proposalId',type:'bytes32'},{name:'version',type:'uint256'},{name:'proposalDigest',type:'bytes32'},{name:'approve',type:'bool'},{name:'reviewer',type:'address'},{name:'nonce',type:'uint256'},{name:'deadline',type:'uint256'}]};
export async function openLocal(stateDir,{existingOnly=false}={}) {
  if(existingOnly && !fs.existsSync(path.join(stateDir,'deployment.json')))throw new Error('Existing local deployment required; verifier never deploys');
  fs.mkdirSync(stateDir,{recursive:true});
  const lock=path.join(stateDir,'operation.lock');
  if(fs.existsSync(lock)) {
    const owner=Number(fs.readFileSync(lock,'utf8'));
    if(!Number.isSafeInteger(owner) || owner<=0)throw new Error('Invalid chain lock; operator review required');
    try {process.kill(owner,0);throw new Error('Local chain is busy');}
    catch(error){if(error.code==='ESRCH')fs.unlinkSync(lock);else throw error;}
  }
  const fd=fs.openSync(lock,'wx');fs.writeSync(fd,String(process.pid));
  let node,provider;
  try {
    node=await startAnvil({stateDir});
    provider=node.provider;
    const signers=await Promise.all([0,1,2,3,4].map(i=>provider.getSigner(i)));
    const addresses=await Promise.all(signers.map(s=>s.getAddress()));
    const signingWallets=node.wallets;
    const deploymentPath=path.join(stateDir,'deployment.json');
    const artifact=compile();
    let contract,deployment;
    if(fs.existsSync(deploymentPath)) {
      deployment=JSON.parse(fs.readFileSync(deploymentPath,'utf8'));
      if(deployment.chain_id!==31337 || keccak256(await provider.getCode(deployment.address))!==deployment.code_hash)throw new Error('Pinned deployment does not match local chain');
      contract=new Contract(deployment.address,artifact.abi,signers[0]);
    } else {
      if(existingOnly)throw new Error('Existing deployment required');
      contract=await new ContractFactory(artifact.abi,artifact.bytecode,signers[0]).deploy(addresses[0]);await contract.waitForDeployment();
      for(const [role,index] of [['PROPOSER_ROLE',1],['REVIEWER_ROLE',2],['VERIFIER_ROLE',3],['SUPPLIER_ROLE',4]])await(await contract.grantRole(await contract[role](),addresses[index])).wait();
      const address=await contract.getAddress(); const receipt=await contract.deploymentTransaction().wait();
      deployment={schema:'ecdat.chain.deployment.v1',network:'local-development',chain_id:31337,address,code_hash:keccak256(await provider.getCode(address)),transaction_hash:receipt.hash,block_number:receipt.blockNumber,block_hash:receipt.blockHash,compiler:artifact.compiler,role_addresses:addresses};
      fs.writeFileSync(deploymentPath,JSON.stringify(deployment,null,2));
    }
    return {provider,contract,deployment,signers,addresses,signingWallets,checkpoint:node.checkpoint,close:async()=>{try{await node.close();}finally{fs.closeSync(fd);fs.unlinkSync(lock);}}};
  } catch(error) {
    if(node)await node.close();fs.closeSync(fd);fs.unlinkSync(lock);throw error;
  }
}
export async function signDecision(contract,wallet,message,chainId=31337n) {
  return wallet.signTypedData({name:'ECDAT EvidenceNotary',version:'1',chainId,verifyingContract:await contract.getAddress()},DECISION_TYPES,message);
}
