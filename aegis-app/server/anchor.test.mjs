import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { buildManifest, canonicalJson, compareRecords, leafHash, manifestHash, memoText, merkleRoot } from './anchor.mjs';
import { createHandler } from './app.mjs';

const records = [{ id: 'CVE-2026-0002', rank: 2, cvss: 7.5, flags: ['nuclei'] }, { id: 'CVE-2026-0001', rank: 1, cvss: null, flags: [] }, { id: 'CVE-2026-0003', rank: 3, nested: { b: 1, a: [2, { d: 1, c: 0 }] } }];
function anchorFor(rows, extra = {}) {
  const manifest = buildManifest({ records: rows, files: {}, createdAt: '2026-11-08T00:00:00.000Z' }), hash = manifestHash(manifest);
  return { version: 1, cluster: 'devnet', manifest, manifestHash: hash, anchors: [{ manifestHash: hash, signature: 'sig1', slot: 10, blockTime: 1700000000 }], ...extra };
}
const config = { apiKey: '', workspaceId: 'test', hfToken: '', hfModel: 'x', hfEndpoint: '', solanaCluster: 'devnet' };
async function get(handler, path) { const req = Readable.from([]); req.url = path; req.method = 'GET'; req.headers = { host: '127.0.0.1:5174' }; let status, body; await handler(req, { writeHead(c) { status = c; }, end(s) { body = JSON.parse(s); } }); return { status, body }; }
const poolOf = rows => ({ query: async () => ({ rows: rows.map(record => ({ record })) }) });
// jsonb reorders keys: simulate it by reversing key order recursively.
const reorder = v => Array.isArray(v) ? v.map(reorder) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).reverse().map(([k, x]) => [k, reorder(x)])) : v;

test('canonical JSON ignores key order; leaf and root are deterministic', () => {
  assert.equal(canonicalJson(records[2]), canonicalJson(reorder(records[2])));
  assert.equal(leafHash(records[0]), leafHash(reorder(records[0])));
  assert.equal(buildManifest({ records, files: {}, createdAt: 't' }).ranking.merkleRoot, buildManifest({ records: [...records].reverse().map(reorder), files: {}, createdAt: 't' }).ranking.merkleRoot);
  assert.equal(merkleRoot(['aa']), 'aa', 'single leaf is the root');
  assert.notEqual(merkleRoot(['aa', 'bb']), merkleRoot(['bb', 'aa']), 'order matters');
});

test('one changed record changes the root and is named', () => {
  const anchor = anchorFor(records);
  assert.deepEqual(compareRecords(anchor, records.map(reorder)).mismatched, []);
  const tampered = records.map(r => r.id === 'CVE-2026-0003' ? { ...r, rank: 499 } : r);
  const result = compareRecords(anchor, tampered);
  assert.deepEqual(result.mismatched, ['CVE-2026-0003']);
  assert.notEqual(result.root, anchor.manifest.ranking.merkleRoot);
  assert.deepEqual(compareRecords(anchor, records.slice(1)).mismatched, ['CVE-2026-0002'], 'a deleted record is reported');
  assert.equal(compareRecords({ ...anchor, manifestHash: 'f'.repeat(64) }, records).manifestIntact, false, 'an edited anchor file is detected');
});

test('integrity endpoint: verified, mismatch, unverifiable, unanchored', async () => {
  const anchor = anchorFor(records), memo = memoText(anchor.manifestHash);
  const make = (pool, opts) => createHandler(pool, { getConfig: () => config, integrity: { loadAnchor: () => anchor, files: () => ({}), ...opts } });
  let calls = 0;
  const ok = await get(make(poolOf(records.map(reorder)), { fetchMemo: async () => { calls++; return { memo, slot: 11, blockTime: 1700000001, failed: false }; } }), '/api/aegis/integrity');
  assert.equal(ok.body.status, 'verified'); assert.equal(ok.body.source, 'tigerdata'); assert.equal(ok.body.slot, 11); assert.match(ok.body.explorerUrl, /cluster=devnet$/); assert.equal(calls, 1);
  const tampered = await get(make(poolOf(records.map(r => r.rank === 1 ? { ...r, rank: 499 } : r)), { fetchMemo: async () => ({ memo, slot: 11 }) }), '/api/aegis/integrity');
  assert.equal(tampered.body.status, 'mismatch'); assert.deepEqual(tampered.body.mismatched, ['CVE-2026-0001']);
  const wrongMemo = await get(make(poolOf(records), { fetchMemo: async () => ({ memo: memoText('0'.repeat(64)), slot: 11 }) }), '/api/aegis/integrity');
  assert.equal(wrongMemo.body.status, 'mismatch'); assert.equal(wrongMemo.body.reason, 'memo_mismatch');
  const offline = await get(make(poolOf(records), { fetchMemo: async () => { throw new Error('rpc down'); } }), '/api/aegis/integrity');
  assert.equal(offline.body.status, 'unverifiable', 'RPC failure is never reported as verified');
  const none = await get(createHandler(null, { getConfig: () => config, integrity: { loadAnchor: () => null } }), '/api/aegis/integrity');
  assert.equal(none.body.status, 'unanchored');
  const changedFile = await get(make(poolOf(records), { files: () => ({ 'ml/top500.csv': 'changed' }), fetchMemo: async () => ({ memo }) }), '/api/aegis/integrity');
  assert.equal(changedFile.body.status, 'mismatch'); assert.equal(changedFile.body.reason, 'files_changed');
});
