import fs from 'node:fs';
import path from 'node:path';
import {JsonRpcProvider,Wallet,NonceManager,ContractFactory,FetchRequest,getAddress,keccak256} from 'ethers';
import {compile,root} from './compile.mjs';

// Public-testnet path only. Never purchases ETH, enables billing, or accepts mainnet.
let provider;
let phase='configuration';
const emit=value=>console.log(JSON.stringify(value));
try {
  const required=['ECDAT_SEPOLIA_RPC','ECDAT_SEPOLIA_DEPLOYER_KEY','ECDAT_PROPOSER_ADDRESS','ECDAT_REVIEWER_ADDRESS','ECDAT_VERIFIER_ADDRESS','ECDAT_SUPPLIER_ADDRESS'];
  const missing=required.filter(name=>!process.env[name]);
  if(missing.length){emit({status:'unconfigured',missing,deployed:false});process.exitCode=1;}
  else {
    const rpc=new URL(process.env.ECDAT_SEPOLIA_RPC);
    if(!['https:','http:'].includes(rpc.protocol))throw new Error('CONFIGURATION_INVALID');
    const request=new FetchRequest(rpc.toString());request.timeout=20000;
    provider=new JsonRpcProvider(request,undefined,{cacheTimeout:-1});
    phase='network-check';
    const network=await provider.getNetwork();
    if(network.chainId!==11155111n)throw new Error('SEPOLIA_CHAIN_ID_REQUIRED');
    const wallet=new Wallet(process.env.ECDAT_SEPOLIA_DEPLOYER_KEY,provider);
    const roles={administrator:getAddress(wallet.address),proposer:getAddress(process.env.ECDAT_PROPOSER_ADDRESS),reviewer:getAddress(process.env.ECDAT_REVIEWER_ADDRESS),verifier:getAddress(process.env.ECDAT_VERIFIER_ADDRESS),supplier:getAddress(process.env.ECDAT_SUPPLIER_ADDRESS)};
    if(Object.values(roles).some(a=>/^0x0{40}$/u.test(a)) || new Set(Object.values(roles).map(a=>a.toLowerCase())).size!==5)throw new Error('FIVE_DISTINCT_ROLE_ADDRESSES_REQUIRED');
    const folder=process.env.ECDAT_SEPOLIA_STATE ? path.resolve(process.env.ECDAT_SEPOLIA_STATE) : path.resolve(root,'../../.ecdat/sepolia');
    fs.mkdirSync(folder,{recursive:true});
    const deploymentPath=path.join(folder,'deployment.json');
    if(fs.existsSync(deploymentPath))throw new Error('DEPLOYMENT_RECORD_EXISTS_REVIEW_BEFORE_REDEPLOY');
    if(fs.existsSync(path.join(folder,'pending-deployment.json')))throw new Error('PENDING_TRANSACTION_REQUIRES_RECONCILIATION');
    phase='compile';const artifact=compile();
    const factory=new ContractFactory(artifact.abi,artifact.bytecode,new NonceManager(wallet));
    const transaction=await factory.getDeployTransaction(roles.administrator);
    phase='balance-check';
    const fees=await provider.getFeeData();const feeCeiling=fees.maxFeePerGas ?? fees.gasPrice;
    if(!feeCeiling || feeCeiling<=0n)throw new Error('FEE_ESTIMATE_UNAVAILABLE');
    const estimatedDeployGas=await provider.estimateGas({...transaction,from:wallet.address});
    // Conservative allowance for four role-enrollment transactions; exact costs vary.
    const estimatedBudgetWei=(estimatedDeployGas+600000n)*feeCeiling*12n/10n;
    const balance=await provider.getBalance(wallet.address);
    if(balance<estimatedBudgetWei){emit({status:'blocked',reason:'Insufficient free Sepolia test ETH; obtain test ETH from an available faucet. No purchase is performed.',deployed:false,chain_id:11155111,balance_wei:balance.toString(),estimated_budget_wei:estimatedBudgetWei.toString()});process.exitCode=1;}
    else {
      phase='deployment-submission';const contract=await factory.deploy(roles.administrator);
      const transactionHash=contract.deploymentTransaction().hash;
      // Preserve the submitted transaction before waiting; uncertain attempts must be reconciled.
      const pendingPath=path.join(folder,'pending-deployment.json');
      fs.writeFileSync(pendingPath,JSON.stringify({schema:'ecdat.chain.pending.v1',chain_id:11155111,transaction_hash:transactionHash,administrator:roles.administrator,roles},null,2),{flag:'wx'});
      phase='deployment-inclusion';await contract.waitForDeployment();const receipt=await contract.deploymentTransaction().wait();
      const address=await contract.getAddress();
      const record={schema:'ecdat.chain.deployment.v1',network:'sepolia-testnet',chain_id:11155111,address,code_hash:keccak256(await provider.getCode(address)),transaction_hash:receipt.hash,block_number:receipt.blockNumber,block_hash:receipt.blockHash,roles,compiler:artifact.compiler,role_transactions:[],status:'included-roles-pending',external_finality:'not_checked',public_source_verification:'not_submitted'};
      fs.writeFileSync(deploymentPath,JSON.stringify(record,null,2),{flag:'wx'});
      fs.writeFileSync(path.join(folder,'EvidenceNotary.json'),JSON.stringify(artifact,null,2));
      phase='role-enrollment';
      for(const [roleName,addressKey] of [['PROPOSER_ROLE','proposer'],['REVIEWER_ROLE','reviewer'],['VERIFIER_ROLE','verifier'],['SUPPLIER_ROLE','supplier']]) {
        const grant=await contract.grantRole(await contract[roleName](),roles[addressKey]);const grantReceipt=await grant.wait();
        record.role_transactions.push({role:addressKey,address:roles[addressKey],transaction_hash:grantReceipt.hash,block_number:grantReceipt.blockNumber});
        fs.writeFileSync(deploymentPath,JSON.stringify(record,null,2));
      }
      phase='finality-observation';record.status='included';
      try {const finalized=await provider.getBlock('finalized');record.external_finality=finalized && finalized.number>=record.role_transactions.at(-1).block_number?'finalized':'included-not-finalized';}catch{record.external_finality='unavailable';}
      fs.writeFileSync(deploymentPath,JSON.stringify(record,null,2));
      emit({...record,deployed:true,deployment_path:deploymentPath,explorer_url:`https://sepolia.etherscan.io/address/${address}`});
    }
  }
} catch(error) {
  // Never print provider errors that could contain an API-key-bearing URL or key material.
  const ownErrors=new Set(['CONFIGURATION_INVALID','SEPOLIA_CHAIN_ID_REQUIRED','FIVE_DISTINCT_ROLE_ADDRESSES_REQUIRED','DEPLOYMENT_RECORD_EXISTS_REVIEW_BEFORE_REDEPLOY','PENDING_TRANSACTION_REQUIRES_RECONCILIATION','FEE_ESTIMATE_UNAVAILABLE']);
  emit({status:'failed',phase,error:ownErrors.has(error.message)?error.message:'Sepolia operation failed; check configured credentials, RPC availability and the persisted pending/deployment records before retrying.',deployed:'check-persisted-records',secrets_logged:false});process.exitCode=1;
} finally {provider?.destroy();}
