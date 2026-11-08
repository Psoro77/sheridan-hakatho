// Tamper-evident anchoring: hash the ranking and ML submission files, commit one hash to Solana
// in a memo transaction, and recompute it later. Only hashes go on-chain, never inventory data.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const MEMO_PREFIX = 'aegis:v1:snapshot:';
export const sha256Hex = data => createHash('sha256').update(data).digest('hex');

/** JSON with recursively sorted object keys, so Postgres jsonb (which reorders keys) hashes the same. */
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().filter(k => value[k] !== undefined).map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  return JSON.stringify(value ?? null);
}

export const leafHash = record => sha256Hex(canonicalJson(record));

/** Leaves keyed by CVE id, from the raw ranking records. */
export const leavesFor = records => Object.fromEntries(records.map(r => [r.id, leafHash(r)]).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));

/** Merkle root over hex leaves (in the given order): pairs hash sha256(left||right), an odd node is carried up. */
export function merkleRoot(leaves) {
  let level = leaves.map(h => Buffer.from(h, 'hex'));
  if (!level.length) return sha256Hex('');
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? createHash('sha256').update(Buffer.concat([level[i], level[i + 1]])).digest() : level[i]);
    level = next;
  }
  return level[0].toString('hex');
}

export function buildManifest({ records, files, createdAt = new Date().toISOString() }) {
  const leaves = leavesFor(records);
  return { files, ranking: { count: records.length, merkleRoot: merkleRoot(Object.values(leaves)), leaves }, createdAt };
}

export const manifestHash = manifest => sha256Hex(canonicalJson(manifest));
export const memoText = hash => `${MEMO_PREFIX}${hash}`;
export const hashFile = path => sha256Hex(readFileSync(path));
export const explorerUrl = (signature, cluster) => `https://explorer.solana.com/tx/${signature}${cluster === 'mainnet-beta' ? '' : `?cluster=${cluster}`}`;

/** Compare current records against an anchor file. Pure: no network. */
export function compareRecords(anchor, records) {
  const expected = anchor.manifest.ranking.leaves, actual = leavesFor(records);
  const mismatched = [...new Set([...Object.keys(expected), ...Object.keys(actual)])].filter(id => expected[id] !== actual[id]).sort();
  return { mismatched, root: merkleRoot(Object.values(actual)), manifestIntact: manifestHash(anchor.manifest) === anchor.manifestHash && merkleRoot(Object.values(expected)) === anchor.manifest.ranking.merkleRoot };
}

async function connection(config) {
  const { Connection, clusterApiUrl } = await import('@solana/web3.js');
  return new Connection(config.solanaRpcUrl || clusterApiUrl(config.solanaCluster || 'devnet'), 'confirmed');
}

/** Read the memo string of a confirmed transaction. Throws on RPC failure or a missing transaction. */
export async function fetchMemo(signature, config) {
  const conn = await connection(config);
  const tx = await conn.getParsedTransaction(signature, { maxSupportedTransactionVersion: 0, commitment: 'confirmed' });
  if (!tx) throw Object.assign(new Error('Transaction not found'), { code: 'TX_NOT_FOUND' });
  const memo = tx.transaction.message.instructions.find(i => i.program === 'spl-memo')?.parsed;
  return { memo: typeof memo === 'string' ? memo : null, slot: tx.slot, blockTime: tx.blockTime ?? null, failed: !!tx.meta?.err };
}

/** Send a memo transaction signed by the keypair and wait for confirmation. */
export async function sendMemo(text, keypair, config) {
  const { Transaction, sendAndConfirmTransaction } = await import('@solana/web3.js');
  const { createMemoInstruction } = await import('@solana/spl-memo');
  const conn = await connection(config);
  const signature = await sendAndConfirmTransaction(conn, new Transaction().add(createMemoInstruction(text, [keypair.publicKey])), [keypair], { commitment: 'confirmed' });
  return { signature, conn };
}

export async function loadKeypair(path) {
  const { Keypair } = await import('@solana/web3.js');
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(path, 'utf8'))));
}
