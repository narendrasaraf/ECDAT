import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import solc from 'solc';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export function compile({writeArtifact=false}={}) {
  const source = fs.readFileSync(path.join(root, 'contracts/EvidenceNotary.sol'), 'utf8');
  const input = {language:'Solidity', sources:{'EvidenceNotary.sol':{content:source}}, settings:{optimizer:{enabled:true,runs:200}, evmVersion:'cancun', outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object']}}}};
  const output = JSON.parse(solc.compile(JSON.stringify(input), {import:(name)=>{
    if (!name.startsWith('@openzeppelin/contracts/') || name.includes('..')) return {error:'Unapproved import'};
    return {contents:fs.readFileSync(path.join(root,'node_modules',name),'utf8')};
  }}));
  const errors = (output.errors ?? []).filter(e=>e.severity === 'error');
  if (errors.length) throw new Error(errors.map(e=>e.formattedMessage).join('\n'));
  const built = output.contracts['EvidenceNotary.sol'].EvidenceNotary;
  const artifact = {contractName:'EvidenceNotary', compiler:solc.version(), evmVersion:'cancun', abi:built.abi, bytecode:'0x'+built.evm.bytecode.object, deployedBytecode:'0x'+built.evm.deployedBytecode.object};
  if(writeArtifact) {
    fs.mkdirSync(path.join(root,'artifacts'),{recursive:true});
    fs.writeFileSync(path.join(root,'artifacts/EvidenceNotary.json'),JSON.stringify(artifact,null,2));
  }
  return artifact;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const artifact=compile({writeArtifact:true});
  console.log(JSON.stringify({compiled:true,compiler:artifact.compiler,contract:artifact.contractName}));
}
