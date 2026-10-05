import fs from 'node:fs';
import path from 'node:path';
import {root} from './compile.mjs';
import {startAnvil} from '../lib/anvil.mjs';

const host='127.0.0.1';
const port=Number(process.env.ECDAT_CHAIN_PORT ?? 8545);
fs.mkdirSync(path.join(root,'.local'),{recursive:true});
const server=await startAnvil({stateDir:path.join(root,'.local'),port});
console.log(JSON.stringify({network:'LOCAL_DEVELOPMENT_ONLY',chainId:31337,rpc:`http://${host}:${port}`,knownDevelopmentKeys:true,independentConsensus:false}));
for (const signal of ['SIGINT','SIGTERM']) process.on(signal,async()=>{await server.close(); process.exit(0);});
