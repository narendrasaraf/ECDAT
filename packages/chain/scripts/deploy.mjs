import fs from 'node:fs';
import path from 'node:path';
import {JsonRpcProvider,ContractFactory,keccak256} from 'ethers';
import {compile,root} from './compile.mjs';

// Deliberately restricted: public-network deployment requires a separately reviewed operation.
const url=process.env.ECDAT_CHAIN_RPC ?? 'http://127.0.0.1:8545';
const parsed=new URL(url);
if (!['127.0.0.1','localhost','[::1]'].includes(parsed.hostname)) throw new Error('This deployment helper permits localhost only');
const provider=new JsonRpcProvider(url);
const network=await provider.getNetwork();
if (network.chainId !== 31337n) throw new Error('Local chain ID must be 31337');
const artifact=compile();
const signers=await Promise.all([0,1,2,3,4].map(i=>provider.getSigner(i)));
const addresses=await Promise.all(signers.map(s=>s.getAddress()));
const contract=await new ContractFactory(artifact.abi,artifact.bytecode,signers[0]).deploy(addresses[0]);
await contract.waitForDeployment();
for (const [role,index] of [['PROPOSER_ROLE',1],['REVIEWER_ROLE',2],['VERIFIER_ROLE',3],['SUPPLIER_ROLE',4]]) {
  await (await contract.grantRole(await contract[role](),addresses[index])).wait();
}
const address=await contract.getAddress();
const receipt=await contract.deploymentTransaction().wait();
const record={schema:'ecdat.chain.deployment.v1',network:'local-development',chain_id:31337,address,code_hash:keccak256(await provider.getCode(address)),transaction_hash:receipt.hash,block_number:receipt.blockNumber,block_hash:receipt.blockHash,roles:{administrator:addresses[0],proposer:addresses[1],reviewer:addresses[2],verifier:addresses[3],supplier:addresses[4]},compiler:artifact.compiler,independent_consensus:false};
fs.mkdirSync(path.join(root,'.local'),{recursive:true});
fs.writeFileSync(path.join(root,'.local','deployment.json'),JSON.stringify(record,null,2));
console.log(JSON.stringify(record));
provider.destroy();
