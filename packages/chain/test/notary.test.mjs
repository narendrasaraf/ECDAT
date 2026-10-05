import test from 'node:test';
import assert from 'node:assert/strict';
import {ContractFactory,id,ZeroHash} from 'ethers';
import {compile} from '../scripts/compile.mjs';
import {DECISION_TYPES,signDecision} from '../lib/local-chain.mjs';
import {startAnvil} from '../lib/anvil.mjs';

test('EvidenceNotary real EVM governance and replay boundaries',async t=>{
  const node=await startAnvil();const provider=node.provider;
  try {
    const signers=await Promise.all([0,1,2,3,4,5].map(i=>provider.getSigner(i)));
    const addresses=await Promise.all(signers.map(s=>s.getAddress()));
    const wallets=node.wallets;
    const artifact=compile();const c=await new ContractFactory(artifact.abi,artifact.bytecode,signers[0]).deploy(addresses[0]);await c.waitForDeployment();
    for(const [role,index] of [['PROPOSER_ROLE',1],['REVIEWER_ROLE',2],['VERIFIER_ROLE',3],['SUPPLIER_ROLE',4]])await(await c.grantRole(await c[role](),addresses[index])).wait();
    const expires=BigInt((await provider.getBlock('latest')).timestamp+3600);
    const propose=async(name,version=1n)=>{const pid=id(name);await(await c.connect(signers[1]).propose(pid,version,id('digest:'+name),expires)).wait();return pid;};
    const message=async(pid,opts={})=>({proposalId:pid,version:1n,proposalDigest:id('digest:'+opts.name),approve:true,reviewer:addresses[2],nonce:await c.nonces(addresses[2]),deadline:expires,...opts});
    const call=(m,s)=>c.decide(m.proposalId,m.version,m.proposalDigest,m.approve,m.reviewer,m.nonce,m.deadline,s);
    const simulate=(m,s)=>c.decide.staticCall(m.proposalId,m.version,m.proposalDigest,m.approve,m.reviewer,m.nonce,m.deadline,s);
    await t.test('records actual approved result with separate actors',async()=>{
      const pid=await propose('valid');const m=await message(pid,{name:'valid'});const sig=await signDecision(c,wallets[2],m);await(await call(m,sig)).wait();
      await(await c.connect(signers[3]).recordResult(pid,1,id('root'),id('bundle'))).wait();
      const p=await c.proposals(pid,1);assert.equal(p.state,5n);assert.equal(p.reviewer,addresses[2]);assert.equal(p.verifier,addresses[3]);assert.equal(p.resultRoot,id('root'));
      await assert.rejects(simulate(m,sig));
    });
    await t.test('rejects stale version while retaining prior proposal',async()=>{
      const pid=await propose('stale');const m=await message(pid,{name:'stale'});const sig=await signDecision(c,wallets[2],m);
      await(await c.connect(signers[1]).propose(pid,2,id('changed'),expires)).wait();await assert.rejects(simulate(m,sig));assert.equal((await c.proposals(pid,1)).digest,m.proposalDigest);
    });
    await t.test('rejects wrong digest, chain, contract, expired deadline and absent role',async()=>{
      const pid=await propose('domain');const m=await message(pid,{name:'domain'});
      const wrongDigest={...m,proposalDigest:id('other')};await assert.rejects(simulate(wrongDigest,await signDecision(c,wallets[2],wrongDigest)));
      await assert.rejects(simulate(m,await signDecision(c,wallets[2],m,1n)));
      const wrongContract=await wallets[2].signTypedData({name:'ECDAT EvidenceNotary',version:'1',chainId:31337,verifyingContract:addresses[5]},DECISION_TYPES,m);await assert.rejects(simulate(m,wrongContract));
      const expired={...m,deadline:1n};await assert.rejects(simulate(expired,await signDecision(c,wallets[2],expired)));
      const outsider={...m,reviewer:addresses[5]};await assert.rejects(simulate(outsider,await signDecision(c,wallets[5],outsider)));
    });
    await t.test('enforces self-review even when administrator grants both roles',async()=>{
      await(await c.grantRole(await c.REVIEWER_ROLE(),addresses[1])).wait();const pid=await propose('self');const m=await message(pid,{name:'self',reviewer:addresses[1],nonce:0n});await assert.rejects(simulate(m,await signDecision(c,wallets[1],m)));
    });
    await t.test('rejects consumed signer nonce on another proposal',async()=>{
      const pid=await propose('nonce');const m=await message(pid,{name:'nonce',nonce:0n});await assert.rejects(simulate(m,await signDecision(c,wallets[2],m)));
    });
    await t.test('requires approved state and separate verifier',async()=>{
      const pid=await propose('crossrole');await assert.rejects(c.connect(signers[3]).recordResult.staticCall(pid,1,id('root'),id('bundle')));
      const m=await message(pid,{name:'crossrole'});await(await call(m,await signDecision(c,wallets[2],m))).wait();
      await(await c.grantRole(await c.VERIFIER_ROLE(),addresses[2])).wait();await assert.rejects(c.connect(signers[2]).recordResult.staticCall(pid,1,id('root'),id('bundle')));
      await assert.rejects(c.connect(signers[5]).recordResult.staticCall(pid,1,id('root'),id('bundle')));
      await(await c.connect(signers[2]).cancel(pid,1)).wait();await assert.rejects(c.connect(signers[3]).recordResult.staticCall(pid,1,id('root'),id('bundle')));
    });
    await t.test('rejected decision cannot record result or be rewritten',async()=>{
      const pid=await propose('reject');const m=await message(pid,{name:'reject',approve:false});const sig=await signDecision(c,wallets[2],m);await(await call(m,sig)).wait();assert.equal((await c.proposals(pid,1)).state,3n);await assert.rejects(simulate(m,sig));await assert.rejects(c.connect(signers[3]).recordResult.staticCall(pid,1,id('root'),id('bundle')));
    });
    await t.test('supplier supersession/revocation preserve historical commitment',async()=>{
      const a=id('supplier1'),b=id('supplier2');await(await c.connect(signers[4]).attest(a,id('capability1'),expires,ZeroHash)).wait();
      await assert.rejects(c.connect(signers[5]).revokeAttestation.staticCall(a,id('reason')));
      await(await c.connect(signers[4]).attest(b,id('capability2'),expires,a)).wait();assert.equal((await c.attestations(a)).supersededBy,b);assert.equal((await c.attestations(a)).digest,id('capability1'));
      await(await c.connect(signers[4]).revokeAttestation(b,id('reason'))).wait();assert.equal((await c.attestations(b)).revoked,true);await assert.rejects(c.connect(signers[4]).revokeAttestation.staticCall(b,id('other')));
      await assert.rejects(c.connect(signers[4]).attest.staticCall(b,id('rewrite'),expires,ZeroHash));
    });
  } finally {await node.close();}
});
