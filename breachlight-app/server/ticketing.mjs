// Ticket handoff: file a defense-plan CVE as a GitHub issue or Jira ticket.
// Ticket text is built here from the ranked record; the browser only sends the CVE id and inventory context.
// Tokens stay server-side. Without a configured provider the route returns a preview, never a fake ticket.
import { z } from 'zod';
import { PublicError } from './errors.mjs';
import { assetSchema, cveId } from './validation.mjs';

export const ticketInput = z.object({ kind: z.literal('cve'), cveId, assets: z.array(assetSchema).max(1000), preview: z.boolean().optional() });
export const ticketKey = input => `cve:${input.cveId}`;

// ---- Ticket content -------------------------------------------------------------------------

const human = s => s.replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
/** Ticket-title subject: the product when known, else the description cut at a word boundary. */
const subjectOf = v => {
  if (v.products?.length) return human(v.products[0].name);
  const d = v.description.replace(/\s+/g, ' ').trim();
  return d.length <= 70 ? d.replace(/\.$/, '') : d.slice(0, 70).replace(/\s+\S*$/, '') + '…';
};
const tierOf = rank => rank <= 100 ? 'Fix now' : 'This week';
const isHttp = url => /^https?:\/\//i.test(url || '');

/** Same product-name matching as the UI: a candidate, not a confirmed affected version. */
export function matchAssets(record, assets) {
  const text = (record.description + ' ' + (record.products || []).map(p => p.vendor + ' ' + p.name.replaceAll('_', ' ')).join(' ')).toLowerCase();
  return assets.filter(a => text.includes(a.product.toLowerCase().replaceAll('_', ' ')));
}

function anchorLines(anchor, cluster) {
  const current = anchor?.anchors?.filter(a => a.manifestHash === anchor.manifestHash).at(-1);
  if (!current) return [];
  const net = anchor.cluster || cluster || 'devnet';
  return [{ text: `Ranking snapshot anchored on Solana ${net} (transaction ${current.signature.slice(0, 10)}…)`, url: `https://explorer.solana.com/tx/${current.signature}${net === 'mainnet-beta' ? '' : `?cluster=${net}`}` }];
}

export function buildCveTicket(record, assets, { workspaceId, includeAssetNames = false, anchor, now = new Date() } = {}) {
  const tier = tierOf(record.rank), ev = record.modelEvidence || {};
  const universe = (ev.universe || 72670).toLocaleString('en-US');
  const matches = matchAssets(record, assets);
  const publicCount = matches.filter(a => a.exposure === 'Public').length;
  const topCriticality = ['High', 'Medium', 'Low'].find(c => matches.some(a => a.criticality === c));
  const why = [
    `Tier: ${tier} (${tier === 'Fix now' ? 'top 100' : 'ranks 101 to 500'}). ${ev.confidence || `Model rank #${record.rank} of ${universe} scoreboard CVEs.`}`,
    ...(ev.reasons || []).map(r => `Driver: ${r}`),
    record.flags?.length ? `Public exploit signals at snapshot ${record.snapshot}: ${record.flags.map(human).join(', ')}.` : `No public exploit signal at snapshot ${record.snapshot}.`,
    record.cvss != null ? `CVSS v3 ${record.cvss.toFixed(1)} (dataset value, investigation context only).` : 'CVSS not available in the dataset.',
    ...(ev.nearest ? [`Most similar past KEV entry: ${ev.nearest.id} (${ev.nearest.product}), similarity ${ev.nearest.similarity.toFixed(2)}.`] : []),
  ];
  const exposure = matches.length
    ? [`${matches.length} asset group${matches.length > 1 ? 's' : ''} match by product name: ${publicCount} public, ${matches.length - publicCount} internal. Highest criticality: ${topCriticality}.`,
       ...(includeAssetNames ? matches.map(a => `${a.name} (${a.product}, ${a.exposure}, ${a.criticality})`) : []),
       'This is a product-name candidate. Confirm installed versions and reachability.']
    : ['No asset group matches this CVE by product name. Confirm whether the software is deployed before closing.'];
  return {
    title: `[Breachlight] ${record.id}: ${subjectOf(record)} (rank #${record.rank}, ${tier})`,
    labels: ['breachlight', 'security', tier === 'Fix now' ? 'fix-now' : 'this-week', ...(record.flags?.length ? ['exploit-signals'] : []), record.id],
    sections: [
      { heading: 'Why Breachlight prioritized this', bullets: why },
      { heading: 'Exposure in your environment', bullets: exposure },
      { heading: 'Vulnerability', text: [record.description.slice(0, 4000), `Published ${record.published} · Weakness ${record.weakness || 'unknown'} · Attack vector ${record.attackVector ? human(record.attackVector.toLowerCase()) : 'unknown'}`] },
      { heading: 'Remediation checklist', tasks: ['Confirm applicability: installed version and the conditions in the vendor advisory', 'Choose a mitigation: vendor patch or documented workaround', 'Test in staging and get change approval', 'Deploy, then recheck exposure', 'Attach evidence of the fix (version, scan or config) before closing'] },
      { heading: 'Evidence', bullets: (record.references || []).filter(r => isHttp(r.url)).map(r => ({ text: r.domain, url: r.url })).concat(record.references?.length ? [] : ['No source references in this snapshot.']) },
      { heading: 'Provenance', bullets: [`Created by Breachlight from workspace ${workspaceId} on ${now.toISOString()}.`, ...anchorLines(anchor), 'Breachlight ranks the likelihood of being added to CISA KEV. It does not confirm exploitation or that your systems are affected.'] },
    ],
  };
}

// ---- Renderers ------------------------------------------------------------------------------

/** Stop dataset text from @-mentioning GitHub users or linking issues (#123). */
const neutralize = s => String(s).replace(/@(?=[\w-])/g, '@​').replace(/#(?=\d)/g, '#​');
const mdUrl = url => url.replace(/[()\s]/g, c => ({ '(': '%28', ')': '%29' })[c] || encodeURIComponent(c));
const mdItem = item => typeof item === 'string' ? neutralize(item) : `[${neutralize(item.text)}](${mdUrl(item.url)})`;

export function toMarkdown(ticket) {
  return ticket.sections.map(s => [`### ${s.heading}`, ...(s.text || []).map(neutralize), [...(s.bullets || []).map(b => `- ${mdItem(b)}`), ...(s.tasks || []).map(t => `- [ ] ${neutralize(t)}`)].join('\n')].filter(Boolean).join('\n\n')).join('\n\n');
}

const adfText = item => typeof item === 'string' ? [{ type: 'text', text: item || ' ' }] : [{ type: 'text', text: item.text || item.url, marks: [{ type: 'link', attrs: { href: item.url } }] }];
const adfPara = item => ({ type: 'paragraph', content: adfText(item) });
const adfList = items => ({ type: 'bulletList', content: items.map(i => ({ type: 'listItem', content: [adfPara(i)] })) });

/** Atlassian Document Format (Jira Cloud REST v3 description). */
export function toAdf(ticket) {
  const content = [];
  for (const s of ticket.sections) {
    content.push({ type: 'heading', attrs: { level: 3 }, content: [{ type: 'text', text: s.heading }] });
    for (const t of s.text || []) content.push(adfPara(t));
    if (s.bullets?.length) content.push(adfList(s.bullets));
    if (s.tasks?.length) content.push(adfList(s.tasks.map(t => `☐ ${t}`)));
  }
  return { type: 'doc', version: 1, content };
}

// ---- Providers ------------------------------------------------------------------------------

/** Which tracker is configured. Never returns credential values. */
export function ticketTarget(config) {
  const github = !!(config.githubToken && config.githubRepo), jira = !!(config.jiraBaseUrl && config.jiraEmail && config.jiraToken && config.jiraProject);
  const provider = config.ticketProvider === 'github' || config.ticketProvider === 'jira' ? config.ticketProvider : github ? 'github' : jira ? 'jira' : null;
  const configured = provider === 'github' ? github : provider === 'jira' ? jira : false;
  const target = provider === 'github' ? config.githubRepo : provider === 'jira' ? config.jiraProject : '';
  return { provider, configured, target: target || '' };
}

function httpsBase(value, name) {
  let url;
  try { url = new URL(value); } catch { throw new PublicError(500, 'TICKET_CONFIG', `${name} is not a valid URL.`); }
  if (url.protocol !== 'https:') throw new PublicError(500, 'TICKET_CONFIG', `${name} must use https.`);
  return url.origin + url.pathname.replace(/\/+$/, '');
}

async function call(fetchImpl, url, init, provider) {
  let res;
  try { res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(15000) }); } catch { throw new PublicError(504, 'TICKET_UNREACHABLE', `${provider} did not respond. Check the network and try again.`); }
  const data = await res.json().catch(() => ({}));
  if (res.ok) return data;
  const detail = provider === 'Jira' ? [...(data.errorMessages || []), ...Object.entries(data.errors || {}).map(([k, v]) => `${k}: ${v}`)].join('; ') : data.message || '';
  const hint = res.status === 401 ? 'the token was rejected' : res.status === 403 ? 'the token lacks permission' : res.status === 404 ? 'the repository or project was not found for this token' : res.status === 410 ? 'issues are disabled on this repository' : res.status === 429 ? 'rate limited, try again shortly' : `HTTP ${res.status}`;
  throw new PublicError(502, 'TICKET_PROVIDER_ERROR', `${provider}: ${hint}${detail ? ` (${String(detail).slice(0, 200)})` : ''}.`);
}

const githubHeaders = config => ({ Authorization: `Bearer ${config.githubToken}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'breachlight-defense', 'Content-Type': 'application/json' });
const jiraHeaders = config => ({ Authorization: `Basic ${Buffer.from(`${config.jiraEmail}:${config.jiraToken}`).toString('base64')}`, Accept: 'application/json', 'Content-Type': 'application/json' });

export async function createTicket(ticket, config, fetchImpl = fetch) {
  const { provider } = ticketTarget(config);
  if (provider === 'github') {
    if (!/^[\w.-]+\/[\w.-]+$/.test(config.githubRepo)) throw new PublicError(500, 'TICKET_CONFIG', 'GITHUB_REPO must look like owner/name.');
    const api = httpsBase(config.githubApiUrl || 'https://api.github.com', 'GITHUB_API_URL');
    const data = await call(fetchImpl, `${api}/repos/${config.githubRepo}/issues`, { method: 'POST', headers: githubHeaders(config), body: JSON.stringify({ title: ticket.title, body: toMarkdown(ticket), labels: ticket.labels }) }, 'GitHub');
    return { provider, externalKey: `#${data.number}`, url: data.html_url };
  }
  if (provider === 'jira') {
    const base = httpsBase(config.jiraBaseUrl, 'JIRA_BASE_URL');
    const fields = { project: { key: config.jiraProject }, issuetype: { name: config.jiraIssueType || 'Task' }, summary: ticket.title.slice(0, 254), description: toAdf(ticket), labels: ticket.labels.map(l => l.replace(/\s+/g, '-')) };
    const data = await call(fetchImpl, `${base}/rest/api/3/issue`, { method: 'POST', headers: jiraHeaders(config), body: JSON.stringify({ fields }) }, 'Jira');
    return { provider, externalKey: data.key, url: `${base}/browse/${data.key}` };
  }
  throw new PublicError(503, 'TICKETING_NOT_CONFIGURED', 'No ticketing provider is configured.');
}

/** Read-only probe for the Connections panel: can this token file issues in the target? */
export async function checkTicketing(config, fetchImpl = fetch) {
  const { provider } = ticketTarget(config);
  try {
    if (provider === 'github') {
      const repo = await call(fetchImpl, `${httpsBase(config.githubApiUrl || 'https://api.github.com', 'GITHUB_API_URL')}/repos/${config.githubRepo}`, { headers: githubHeaders(config) }, 'GitHub');
      if (!repo.has_issues) return { ok: false, message: 'Issues are disabled on this repository.' };
      return { ok: true, message: `${repo.private ? 'Private' : 'Public'} repository${repo.private ? '' : '. Ticket text is visible to anyone'}.`, private: !!repo.private };
    }
    if (provider === 'jira') {
      const project = await call(fetchImpl, `${httpsBase(config.jiraBaseUrl, 'JIRA_BASE_URL')}/rest/api/3/project/${encodeURIComponent(config.jiraProject)}`, { headers: jiraHeaders(config) }, 'Jira');
      return { ok: true, message: `Project ${project.key}: ${project.name}.` };
    }
  } catch (e) { return { ok: false, message: e instanceof PublicError ? e.message : 'Check failed.' }; }
  return { ok: false, message: 'Not configured.' };
}

// ---- Routes ---------------------------------------------------------------------------------

export const TICKET_TABLE = `CREATE TABLE IF NOT EXISTS breachlight_app.tickets (
 workspace_id text NOT NULL,
 ticket_key text NOT NULL,
 provider text NOT NULL,
 external_key text NOT NULL,
 url text NOT NULL,
 title text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (workspace_id, ticket_key, provider)
)`;

export function ticketRoutes(pool, { findRecord, loadAnchor = () => null, fetchImpl = fetch, now = () => new Date() } = {}) {
  const memory = new Map(), inFlight = new Map();
  let ready = null, probe = null;
  const ensure = () => ready ??= pool.query(TICKET_TABLE).catch(e => { ready = null; throw e; });
  async function list(config) {
    if (pool) { try { await ensure(); const r = await pool.query('SELECT ticket_key AS key, provider, external_key AS "externalKey", url, title, created_at AS "createdAt" FROM breachlight_app.tickets WHERE workspace_id=$1 ORDER BY created_at', [config.workspaceId]); return r.rows; } catch {} }
    return [...(memory.get(config.workspaceId)?.values() || [])];
  }
  async function build(input, config) {
    const context = { workspaceId: config.workspaceId, includeAssetNames: config.ticketIncludeAssetNames, anchor: (() => { try { return loadAnchor(); } catch { return null; } })(), now: now() };
    const record = await findRecord(input.cveId);
    if (!record) throw new PublicError(404, 'CVE_NOT_FOUND', 'This CVE is not in the ranked snapshot.');
    return buildCveTicket(record, input.assets, context);
  }
  async function create(key, ticket, config, target) {
    const existing = (await list(config)).find(t => t.key === key && t.provider === target.provider);
    if (existing) return { mode: 'existing', ticket: existing };
    const made = await createTicket(ticket, config, fetchImpl);
    const row = { key, provider: made.provider, externalKey: made.externalKey, url: made.url, title: ticket.title, createdAt: now().toISOString() };
    let persisted = false;
    if (pool) {
      try {
        await ensure();
        await pool.query('INSERT INTO breachlight_app.tickets(workspace_id,ticket_key,provider,external_key,url,title) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING', [config.workspaceId, key, row.provider, row.externalKey, row.url, row.title]);
        await pool.query('INSERT INTO breachlight_app.events(workspace_id,event_type,details) VALUES($1,$2,$3)', [config.workspaceId, 'ticket_created', JSON.stringify({ key, provider: row.provider, externalKey: row.externalKey })]);
        persisted = true;
      } catch {}
    }
    if (!persisted) {
      if (!memory.has(config.workspaceId)) memory.set(config.workspaceId, new Map());
      memory.get(config.workspaceId).set(`${key}|${row.provider}`, row);
    }
    return { mode: 'created', ticket: row, persisted };
  }
  return {
    async status(config) {
      const target = ticketTarget(config);
      if (!target.configured) return { ...target, ok: false, message: 'Not configured' };
      const sig = `${target.provider}|${target.target}|${config.githubToken || config.jiraToken}`;
      if (!probe || probe.sig !== sig || Date.now() - probe.at > 60000) probe = { sig, at: Date.now(), value: checkTicketing(config, fetchImpl) };
      return { ...target, ...(await probe.value) };
    },
    async handle(path, req, config, readBody) {
      if (path !== '/api/breachlight/tickets') return null;
      if (req.method === 'GET') return { ...ticketTarget(config), tickets: await list(config) };
      if (req.method !== 'POST') return null;
      const parsed = ticketInput.safeParse(await readBody(req));
      if (!parsed.success) throw new PublicError(400, 'INVALID_TICKET', 'Select a valid CVE from the ranked snapshot.');
      const input = parsed.data, key = ticketKey(input), target = ticketTarget(config);
      const ticket = await build(input, config);
      if (input.preview || !target.configured) return { mode: 'preview', key, provider: target.provider, configured: target.configured, title: ticket.title, labels: ticket.labels, markdown: toMarkdown(ticket) };
      const flight = `${config.workspaceId}|${key}|${target.provider}`;
      if (!inFlight.has(flight)) { const p = create(key, ticket, config, target); inFlight.set(flight, p); p.finally(() => inFlight.delete(flight)).catch(() => {}); }
      return await inFlight.get(flight);
    },
  };
}
