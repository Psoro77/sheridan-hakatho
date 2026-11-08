// Commit the ML submission files and the 500 ranking records to Solana in one memo transaction.
// Writes public/data/anchor.json (commit it: git history pins the first signature).
// Usage: node scripts/anchor-snapshot.mjs [--dry-run]
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { buildManifest, explorerUrl, hashFile, loadKeypair, manifestHash, memoText, sendMemo } from '../server/anchor.mjs';
import { loadConfig } from '../server/config.mjs';

const FILES = ['ml/top500.csv', 'ml/outputs/top500.csv', 'ml/outputs/predictions.parquet', 'ml/outputs/metrics.json', 'ml/models/final_meta.json'];
const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const anchorPath = new URL('../public/data/anchor.json', import.meta.url);
const dryRun = process.argv.includes('--dry-run');
const config = loadConfig();

const records = JSON.parse(readFileSync(new URL('../public/data/intelligence.json', import.meta.url), 'utf8')).vulnerabilities;
const files = Object.fromEntries(FILES.filter(f => existsSync(repoRoot + f)).map(f => [f, hashFile(repoRoot + f)]));
const previous = existsSync(anchorPath) ? JSON.parse(readFileSync(anchorPath, 'utf8')) : null;
// Keep createdAt when nothing changed, so the manifest hash is stable across runs.
let manifest = buildManifest({ records, files });
if (previous) {
  const same = buildManifest({ records, files, createdAt: previous.manifest.createdAt });
  if (manifestHash(same) === previous.manifestHash) manifest = same;
}
const hash = manifestHash(manifest);
console.log(`records: ${records.length} | merkle root: ${manifest.ranking.merkleRoot}`);
for (const [f, h] of Object.entries(files)) console.log(`  ${f}: ${h.lf || h.raw}`);
console.log(`manifest hash: ${hash}\nmemo: ${memoText(hash)}`);
const already = previous?.manifestHash === hash && previous.anchors.some(a => a.manifestHash === hash);
if (dryRun) { console.log(already ? 'Already anchored (dry run).' : 'Dry run: nothing sent.'); process.exit(0); }
if (already) { console.log('This exact manifest is already anchored:', previous.anchors.findLast(a => a.manifestHash === hash).signature); process.exit(0); }

const keypair = await loadKeypair(config.solanaKeypairPath);
const { signature, conn } = await sendMemo(memoText(hash), keypair, config);
const tx = await conn.getTransaction(signature, { maxSupportedTransactionVersion: 0, commitment: 'confirmed' });
const entry = { manifestHash: hash, signature, slot: tx?.slot ?? null, blockTime: tx?.blockTime ?? null, signer: keypair.publicKey.toBase58() };
const anchor = { version: 1, cluster: config.solanaCluster, manifest, manifestHash: hash, anchors: [...(previous?.anchors || []), entry] };
writeFileSync(anchorPath, JSON.stringify(anchor, null, 1) + '\n');
console.log(`Anchored at slot ${entry.slot}: ${explorerUrl(signature, config.solanaCluster)}`);
