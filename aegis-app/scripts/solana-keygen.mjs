// Create the server's Solana signing keypair (gitignored) and fund it on devnet.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { Connection, Keypair, LAMPORTS_PER_SOL, clusterApiUrl } from '@solana/web3.js';
import { loadConfig } from '../server/config.mjs';

const config = loadConfig(), path = config.solanaKeypairPath;
let keypair;
if (existsSync(path)) {
  keypair = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(path, 'utf8'))));
  console.log('Using existing keypair:', path);
} else {
  keypair = Keypair.generate();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(Array.from(keypair.secretKey)), { mode: 0o600 });
  console.log('Created keypair:', path);
}
const address = keypair.publicKey.toBase58();
console.log('Address:', address, '| cluster:', config.solanaCluster);
const conn = new Connection(config.solanaRpcUrl || clusterApiUrl(config.solanaCluster), 'confirmed');
let balance = await conn.getBalance(keypair.publicKey);
if (config.solanaCluster === 'devnet' && balance < 0.01 * LAMPORTS_PER_SOL) {
  try {
    const sig = await conn.requestAirdrop(keypair.publicKey, LAMPORTS_PER_SOL);
    await conn.confirmTransaction({ signature: sig, ...(await conn.getLatestBlockhash()) }, 'confirmed');
    balance = await conn.getBalance(keypair.publicKey);
  } catch (e) {
    console.log(`Airdrop failed (${e.message.slice(0, 120)}). Fund it at https://faucet.solana.com (devnet) with address ${address}`);
  }
}
console.log('Balance:', balance / LAMPORTS_PER_SOL, 'SOL');
