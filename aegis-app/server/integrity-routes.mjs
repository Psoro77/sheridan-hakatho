// GET /api/aegis/integrity: recompute the ranking and submission hashes and check them against the
// Solana memo recorded in public/data/anchor.json. RPC failure reports `unverifiable`, never `verified`.
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { compareRecords, explorerUrl, fetchMemo as fetchMemoDefault, hashFile, memoText } from './anchor.mjs';

const anchorPath = new URL('../public/data/anchor.json', import.meta.url);
const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
export const loadAnchorFile = () => existsSync(anchorPath) ? JSON.parse(readFileSync(anchorPath, 'utf8')) : null;
function checkFiles(files) {
  return Object.fromEntries(Object.entries(files || {}).map(([path, hash]) => {
    const full = repoRoot + path;
    return [path, existsSync(full) ? (hashFile(full) === hash ? 'match' : 'changed') : 'missing'];
  }));
}

export function integrityRoutes(pool, { fallbackRecords, loadAnchor = loadAnchorFile, fetchMemo = fetchMemoDefault, files = checkFiles } = {}) {
  const chainCache = new Map();
  async function chain(signature, config) {
    const hit = chainCache.get(signature);
    if (hit && Date.now() - hit.at < 60000) return hit.value;
    const value = await fetchMemo(signature, config);
    chainCache.set(signature, { at: Date.now(), value });
    return value;
  }
  async function records() {
    if (pool) { try { const r = await pool.query('SELECT record FROM aegis_app.vulnerabilities'); if (r.rows.length) return { source: 'tigerdata', records: r.rows.map(x => x.record) }; } catch {} }
    return { source: 'snapshot', records: fallbackRecords };
  }
  return async (path, req, config) => {
    if (path !== '/api/aegis/integrity' || req.method !== 'GET') return null;
    const anchor = loadAnchor();
    const cluster = anchor?.cluster || config.solanaCluster || 'devnet';
    const current = anchor?.anchors?.filter(a => a.manifestHash === anchor.manifestHash).at(-1);
    if (!anchor || !current) return { status: 'unanchored', cluster };
    const { source, records: rows } = await records();
    const local = compareRecords(anchor, rows), fileStatus = files(anchor.manifest.files);
    const first = anchor.anchors.map(a => a.blockTime).filter(Boolean).sort((a, b) => a - b)[0] ?? null;
    const base = { cluster, signature: current.signature, explorerUrl: explorerUrl(current.signature, cluster), slot: current.slot, blockTime: current.blockTime, firstAnchoredAt: first, source, merkleRoot: anchor.manifest.ranking.merkleRoot, mismatched: local.mismatched, files: fileStatus, manifestIntact: local.manifestIntact };
    if (!local.manifestIntact || local.mismatched.length || Object.values(fileStatus).includes('changed')) return { ...base, status: 'mismatch', reason: !local.manifestIntact ? 'anchor_file_altered' : local.mismatched.length ? 'records_changed' : 'files_changed' };
    let onChain;
    try { onChain = await chain(current.signature, { ...config, solanaCluster: cluster }); } catch { return { ...base, status: 'unverifiable', reason: 'rpc_unavailable' }; }
    if (onChain.failed || onChain.memo !== memoText(anchor.manifestHash)) return { ...base, status: 'mismatch', reason: 'memo_mismatch' };
    return { ...base, status: 'verified', slot: onChain.slot, blockTime: onChain.blockTime ?? current.blockTime };
  };
}
