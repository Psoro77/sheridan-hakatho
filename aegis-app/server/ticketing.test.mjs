import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createHandler } from './app.mjs';
import { buildCveTicket, toAdf, toMarkdown, ticketTarget } from './ticketing.mjs';

const base = { apiKey: '', workspaceId: 'test', hfToken: '', hfModel: 'm', hfEndpoint: '', graniteProvider: 'huggingface' };
const github = { ...base, githubToken: 'ghp_secret', githubRepo: 'acme/security', githubApiUrl: 'https://api.github.com' };
const jira = { ...base, jiraBaseUrl: 'https://acme.atlassian.net/', jiraEmail: 'sec@acme.test', jiraToken: 'jira-secret', jiraProject: 'SEC', jiraIssueType: 'Task' };
const assets = [{ id: 'a1', name: 'Customer portal', product: 'spip', exposure: 'Public', criticality: 'High' }];
const record = { id: 'CVE-2026-1', rank: 3, description: 'SPIP flaw reported by @someone, see #12.', published: '2026-08-01', snapshot: '2026-08', cvss: 9.8, flags: ['nuclei'], products: [], references: [{ url: 'https://vendor.test/a (1)', domain: 'vendor.test', tags: '' }], attackVector: 'NETWORK', weakness: 'CWE-94' };

async function request(handler, path, method = 'GET', data) {
  const req = Readable.from(data ? [JSON.stringify(data)] : []);
  req.url = path; req.method = method; req.headers = { host: '127.0.0.1:5174' };
  let status, payload;
  await handler(req, { writeHead(code) { status = code; }, end(s) { payload = JSON.parse(s); } });
  return { status, body: payload };
}
function fakeFetch(reply) {
  const calls = [];
  const fn = async (url, init) => { calls.push({ url, init, body: init.body ? JSON.parse(init.body) : null }); const [status, data] = reply(url, init); return { ok: status < 300, status, json: async () => data }; };
  fn.calls = calls;
  return fn;
}
const handler = (config, fetchImpl) => createHandler(null, { getConfig: () => config, tickets: { fetchImpl } });

test('ticket text neutralizes mentions and issue links, keeps a checklist, and ADF has no empty text', () => {
  const ticket = buildCveTicket(record, assets, { workspaceId: 'w' });
  const md = toMarkdown(ticket);
  assert.ok(!/@someone/.test(md) && !/#12/.test(md), 'dataset text must not ping users or link issues');
  assert.match(md, /- \[ \] Confirm applicability/);
  assert.match(md, /\(https:\/\/vendor\.test\/a%20%281%29\)/);
  assert.match(md, /1 asset group match by product name: 1 public/);
  assert.ok(!md.includes('Customer portal'), 'asset names are excluded unless TICKET_INCLUDE_ASSET_NAMES is set');
  assert.ok(buildCveTicket(record, assets, { workspaceId: 'w', includeAssetNames: true }).sections[1].bullets.some(b => String(b).includes('Customer portal')));
  const walk = n => (n.type === 'text' ? assert.ok(n.text.length > 0) : (n.content || []).forEach(walk));
  walk(toAdf(ticket));
});

test('provider selection is explicit, and status never exposes tokens', async () => {
  assert.equal(ticketTarget(base).provider, null);
  assert.equal(ticketTarget({ ...github, ...jira }).provider, 'github');
  assert.equal(ticketTarget({ ...github, ...jira, ticketProvider: 'jira' }).provider, 'jira');
  const f = fakeFetch(() => [200, { has_issues: true, private: true }]);
  const status = await request(handler(github, f), '/api/aegis/status');
  assert.equal(status.body.ticketing.ok, true);
  assert.ok(!JSON.stringify(status.body).includes('ghp_secret'));
});

test('without a provider the route returns a preview and calls nothing', async () => {
  const f = fakeFetch(() => [500, {}]);
  const r = await request(handler(base, f), '/api/aegis/tickets', 'POST', { kind: 'cve', cveId: 'CVE-2026-77806', assets: [] });
  assert.equal(r.status, 200);
  assert.equal(r.body.mode, 'preview');
  assert.equal(r.body.key, 'cve:CVE-2026-77806');
  assert.match(r.body.markdown, /### Remediation checklist/);
  assert.equal(f.calls.length, 0);
});

test('GitHub issue is created once per item; a repeat returns the existing issue', async () => {
  const snapshot = await request(handler(base), '/api/aegis/intelligence');
  const cve = snapshot.body.vulnerabilities[0].id;
  const f = fakeFetch(() => [201, { number: 42, html_url: 'https://github.com/acme/security/issues/42' }]);
  const h = handler(github, f);
  const first = await request(h, '/api/aegis/tickets', 'POST', { kind: 'cve', cveId: cve, assets: [] });
  assert.equal(first.body.mode, 'created');
  assert.equal(first.body.ticket.externalKey, '#42');
  assert.equal(f.calls[0].url, 'https://api.github.com/repos/acme/security/issues');
  assert.equal(f.calls[0].init.headers.Authorization, 'Bearer ghp_secret');
  assert.ok(f.calls[0].body.labels.includes('fix-now'));
  const again = await request(h, '/api/aegis/tickets', 'POST', { kind: 'cve', cveId: cve, assets: [] });
  assert.equal(again.body.mode, 'existing');
  assert.equal(f.calls.length, 1);
  assert.equal((await request(h, '/api/aegis/tickets')).body.tickets[0].url, 'https://github.com/acme/security/issues/42');
});

test('Jira ticket uses basic auth, ADF and a browse link; provider errors are explained', async () => {
  const f = fakeFetch(() => [201, { key: 'SEC-7' }]);
  const r = await request(handler(jira, f), '/api/aegis/tickets', 'POST', { kind: 'cve', cveId: 'CVE-2026-77806', assets: [] });
  assert.equal(r.body.ticket.url, 'https://acme.atlassian.net/browse/SEC-7');
  assert.equal(f.calls[0].url, 'https://acme.atlassian.net/rest/api/3/issue');
  assert.equal(f.calls[0].init.headers.Authorization, `Basic ${Buffer.from('sec@acme.test:jira-secret').toString('base64')}`);
  assert.equal(f.calls[0].body.fields.description.type, 'doc');
  const bad = fakeFetch(() => [400, { errors: { issuetype: 'Specify a valid issue type' } }]);
  const err = await request(handler(jira, bad), '/api/aegis/tickets', 'POST', { kind: 'cve', cveId: 'CVE-2026-77806', assets: [] });
  assert.equal(err.status, 502);
  assert.match(err.body.error, /issuetype: Specify a valid issue type/);
  assert.ok(!err.body.error.includes('jira-secret'));
});

test('invalid input and unknown CVEs fail before any provider call', async () => {
  const f = fakeFetch(() => [201, {}]);
  const h = handler(github, f);
  assert.equal((await request(h, '/api/aegis/tickets', 'POST', { kind: 'cve', cveId: 'not-a-cve', assets: [] })).status, 400);
  assert.equal((await request(h, '/api/aegis/tickets', 'POST', { kind: 'cve', cveId: 'CVE-2026-9999999', assets: [] })).status, 404);
  assert.equal(f.calls.length, 0);
});
