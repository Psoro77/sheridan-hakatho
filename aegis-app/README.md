# Aegis application

A responsive security-intelligence workspace built with React, Vinext, Recharts, and Lucide. It uses the repository's saved ML ranking and a browser-safe snapshot of IBM challenge data.

## Run locally

Use Node 22.13+ (a supported LTS is recommended).

```sh
npm run install:ci
npm run dev
```

The dev server prints the local URL. `npm run build` builds the application for deployment.

## Data

From this directory, run `python3 scripts/prepare-data.py` to regenerate `public/data/intelligence.json`. This reads `../ml/top500.csv` and CSVs in `../IBM/data/`. No trained model or Python ML environment is required to serve the saved snapshot.

Includes all 500 ranked CVEs, descriptions, available CVSS, snapshot exploit flags, up to five products and four dataset references per CVE, and aggregate snapshot-month counts from the 72,670-row scoreboard. Product/version metadata and references are investigation context, not additions to the trained model. Missing CVSS is shown explicitly and omitted from the severity scatterplot.

## Workflows

- Overview: real model-rank versus severity scatterplot, actual monthly scoreboard volume, and the highest-ranked CVEs.
- Vulnerability intelligence: search, filters, CSV export, evidence drawer, add to plan.
- Inventory: CSV/JSON import with validation, editable exposure and criticality, product-name candidate matches. A local working copy is retained; Save workspace persists it to TigerData.
- Contextual priority: rank percentile × normalized severity × exposure × criticality. Public/internal exposure weights are 1/0.45; high/medium/low criticality weights are 1/0.75/0.5. Missing severity uses a disclosed 0.5 fallback. My inventory sorts by this index. It is not a calibrated probability or a confirmed vulnerability match.
- Defense plan: queue, evidence-review state, Markdown export, browser working copy, and TigerData persistence.

## Installed npm software assessment

The overview now starts with **How exposed is your stack?** Upload `package-lock.json` (npm lockfile versions 1, 2, or 3) or enter exact `package@version` pairs. Exact-pinned `package.json` entries are supported; ranges such as `^1.7.0` are excluded because they do not establish the installed version. Uploaded files are parsed in the browser. Only normalized package names and exact versions are sent to OSV.dev. Private/non-public registry URLs and local/workspace links are excluded; the report states excluded counts. Up to 2,000 unique package/version pairs are supported.

The scanner uses OSV batch queries, follows pagination when retrieving full advisory records, and treats failed lookups as **unknown**, never clear. It shows affected unique package/version pairs, distinct advisories, direct/transitive classification where the lockfile supports it, development-only status, and a clickable package footprint. A v1 lockfile does not reliably distinguish hoisted top-level transitive packages, so those relationships are marked unknown. Manual input is explicitly treated as direct dependencies.

Each affected package has an evidence panel with advisory text, source links, documented fixed versions, and an actionable remediation checklist. Upgrade candidates come only from fixed events for the matching npm package, must be newer than the installed version, and are queried again against OSV. At most three candidates are checked, preferring the same major version; a candidate is shown only when its recheck returns no current advisories. This is not a guarantee of security or compatibility and is not necessarily the lowest possible fixed version. Transitive packages receive parent-dependency guidance rather than an unsafe automatic direct-install suggestion. Commands are displayed for review and are never executed.

Granite's **Explain with Granite** action uses server-loaded, saved advisory evidence plus the declared application exposure. It does not receive the original filename or dependency paths. It explains the flaw, exploitation prerequisites supported by advisory text, corrective steps, and remaining unknowns. The application has not analyzed source-code reachability or executed exploits. Current OSV matching is independent of the historical top-500 benchmark; a historical CVE rank is included only when an alias matches the saved ranking.

Scans and generated package explanations persist in the `aegis_app.dependency_scans` and `aegis_app.dependency_briefings` tables. Run `node scripts/migrate-dependencies.mjs` once when setting up another database. A **Fix plan** Markdown export provides all affected packages, upgrade guidance, and evidence links. The example scan is labeled as example data, not as this user's installed inventory.

Validation: `npm run test:server` includes lockfile parsing, private/range exclusions, version comparison, advisory pagination, withdrawn entries, failed lookups, and upgrade verification. `node scripts/check-connections.mjs --dependency-scan` performs an example Axios/Chalk scan through the app API, saves it to TigerData, generates one local briefing, and checks the cache.

References: [OSV package/version API](https://google.github.io/osv.dev/post-v1-query/), [batch and pagination API](https://google.github.io/osv.dev/post-v1-querybatch/), [OSV affected-version schema](https://ossf.github.io/osv-schema/), [npm lockfile format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

## Live TigerData and Granite integrations

The application now uses a server-only Node API in `server/`. `npm run dev` starts that API on localhost:5174 and the UI on localhost:5173. Vite proxies `/api/aegis/*` to the API. The browser receives neither database credentials nor the Hugging Face token.

### TigerData

The backend reads `TIGERDATA_URL` or, locally, the repository-root `tiger-cloud-db-11853-credentials.txt`. The credential file is ignored by Git. Set `TIGERDATA_CREDENTIALS_FILE` for another path. PostgreSQL uses TLS with certificate verification enabled.

`npm run db:seed` creates the additive `aegis_app` schema and upserts the prepared snapshot. It does not truncate or modify other schemas. The database contains ranked CVE records, monthly aggregates, inventory/plan workspaces, validated AI briefings, and workspace-save audit events. It does not yet contain the original embedding vectors.

The UI reads its intelligence from TigerData, falling back to an explicitly labeled bundled snapshot if unavailable. **Save workspace** stores inventory and defense-plan changes. Local browser storage remains a working copy. Revision checks prevent overwriting another tab's saved edits; reload after a conflict. This is one team workspace (`AEGIS_WORKSPACE_ID`, default `sheridan-labs`), not a multi-tenant identity system.

### Local IBM Granite through Ollama (active configuration)

Aegis is configured to use the installed `granite4:latest` model through Ollama:

```dotenv
GRANITE_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=granite4:latest
```

Keep Ollama running. **Connections** checks `/api/tags` and reports whether the actual model is available. **Generate with Granite** runs `/api/chat` locally with a JSON output schema, validates the result, and caches it in TigerData. No HF token is sent and there is no automatic fallback to a hosted provider. Internal asset names are still excluded from prompts. Briefings are stored in the cloud database, although inference itself runs on this Mac.

Local generation has a three-minute timeout to accommodate model loading and slower machines. Only one uncached local briefing runs through the API at a time; duplicate concurrent requests share the same result. Cached responses are separated by provider, model, prompt version, and evidence. A first request may take longer while Ollama loads the model.

To explicitly switch back to the hosted integration, set `GRANITE_PROVIDER=huggingface`. Existing HF settings are preserved. Changing provider/model settings requires no API restart; changing server code does.

Reference: [Ollama chat API](https://docs.ollama.com/api/chat), [structured outputs](https://docs.ollama.com/capabilities/structured-outputs).

### IBM Granite through Hugging Face

Add these server-only settings to `.env.local` (already ignored by Git):

```dotenv
HF_TOKEN=your_token_here
HF_MODEL_ID=ibm-granite/granite-4.2-8b:deepinfra
```

The token needs Inference Providers permission and available inference credits. No dedicated deployment is required for the default shared-provider model. Configuration is reread for each request, so adding a token requires no API restart.

Open a CVE and select **Generate with Granite**. The backend supplies public CVE evidence and aggregate matched exposure/criticality counts. It excludes internal asset names. The prompt distinguishes observed evidence from unknown applicability and does not claim to have fetched vendor advisory contents. Generated JSON is schema-validated; successful results are cached in TigerData by model, prompt version, and evidence hash. No fallback text is misrepresented as live AI.

A dedicated Hugging Face endpoint is also supported using `HF_ENDPOINT_URL` and `HF_API_MODE=chat` (default) or `text-generation`. Use a Granite model matching your deployed endpoint. Non-Hugging-Face endpoint hosts are rejected before forwarding the token.

Errors distinguish missing tokens, authorization, credit/billing problems (HTTP 402), rate limits, invalid output, and timeouts. Configuration alone is not proof of successful inference. The initial hosted test returned HTTP 402. HF billing/credits are needed only when explicitly selecting the Hugging Face provider; the active local Ollama provider does not depend on them.

### Verification and deployment

```sh
npm run test:server
npx tsc --noEmit
npm run build
node scripts/check-connections.mjs --verify
# Optional live model call; uses the selected provider and saves the validated response:
node scripts/check-connections.mjs --generate
```

The database integration was verified with a TLS connection, 500-record read, 72,670-row aggregate check, and a write/read transaction that was rolled back. API status, intelligence, and workspace routes were checked through the UI's proxy. Browser QA is performed by the user.

The live backend currently runs locally. The prior Sites Worker build cannot connect directly to PostgreSQL through this Node companion. To host this integrated version, deploy the Node API on a TCP-capable server and configure an authenticated reverse proxy from the frontend; do not expose database credentials to the client. Bind beyond localhost only with `AEGIS_API_KEY`. The API requires that bearer key in that mode. Production also needs proper user/workspace authorization before expanding access beyond the private team demo. A public unauthenticated API is not provided.

Entire workflow integration remains planned. Solana anchoring is described below. Version-aware CPE matching, topology ingestion, and semantic search over embedding vectors remain separate work.

Sources: [Hugging Face supported models](https://huggingface.co/inference/models), [chat completion API](https://huggingface.co/docs/inference-providers/tasks/chat-completion), [dedicated endpoints](https://huggingface.co/docs/inference-endpoints/guides/test_endpoint), [node-postgres TLS](https://node-postgres.com/features/ssl).

## Evaluation disclosure

2025 out-of-time evaluation (disjoint folds V1 and V2, scored at scoreboard depth): the numbers shown in the UI are read from `../ml/outputs/metrics.json` and `../ml/outputs/rank_bands.csv` by `scripts/prepare-data.py`; nothing is hardcoded. These are saved results, not a new evaluation. Exploitation-language features remain a disclosed leakage risk. See `../ml/docs/findings.md`.

### Project-first overview and agent handoff

Overview starts with GitHub import or upload/paste of an npm JSON manifest. Saved example scans do not bypass onboarding; real saved scans restore automatically. GitHub imports read the default branch via the public Contents API, prefer `package-lock.json`, and support a project subfolder. This is a one-time public import, not OAuth or continuous sync. Private repositories use file upload. Exact versions only; manifest ranges remain excluded.

Affected package details offer **Fix with an agent**. A reviewable prompt includes the installed version, dependency relationship, checked upgrade candidate, advisory URLs and verification steps. It copies to the clipboard and uses documented Cursor / Claude Code deep links. Claude requires a valid local directory and a registered URL handler; Cursor requires the intended project already open. Neither opens automatically until clicked, executes a fix, nor marks remediation complete. Clipboard and manual-paste fallbacks remain available. The handoff supplies at most eight advisory references and explicitly asks the agent to review all matches before closing.

Reference: [GitHub Contents API](https://docs.github.com/en/rest/repos/contents), [Cursor deep links](https://prod.cursor.com/docs/reference/deeplinks), [Claude Code deep links](https://code.claude.com/docs/en/deep-links).

### Model-aware remediation priority

Overview sorts affected packages using `aegis-context-v1`, a transparent triage heuristic—not calibrated exploitation probability or fresh model inference. Each advisory gets severity points (critical 40, high 30, moderate/medium 20, low 10; unknown 30), declared exposure points (internal 10, public or unknown 20), and historical model points (rank #1 = 40 to #500 = 20). Missing model coverage gets a neutral 20, with an explicit Not scored label. Matching uses exact advisory IDs/CVE aliases against the saved top-500 ranking.

The highest-scoring advisory drives the package score, avoiding mixing one advisory's severity with another's model rank. Scores 80+ mean Review first; 60–79 Review next; lower scores Scheduled review. These thresholds and weights are product triage conventions, not empirically validated risk thresholds. Unknown status receives no score; development dependencies get no discount. Equal scores sort by package key. Partial model coverage is visible. Both existing scans and new scans receive the current policy; persisted advisory observations remain unchanged when reading old scans. Priority context flows into Granite evidence, exported plans, and editor handoff prompts.

## Solana anchoring (tamper-evident ranking)

TigerData holds the ranked top 500, so anyone with database access could quietly change a rank. Aegis commits to the data on Solana so such a change is **visible**. This is tamper-evident, not tamper-proof: it detects edits, it does not prevent them. Only hashes go on-chain, never inventory, asset names or plans.

What is anchored, in one memo transaction `aegis:v1:snapshot:<manifest sha256>` (manifest in [`public/data/anchor.json`](public/data/anchor.json)):

- SHA-256 of `ml/top500.csv`, `ml/outputs/top500.csv`, `ml/outputs/predictions.parquet`, `ml/outputs/metrics.json`, `ml/models/final_meta.json`. Text files also carry an `lf` hash with CRLF normalized to LF, because Git on Windows rewrites line endings; a Linux or macOS clone matches `lf`.
- A Merkle root over the 500 ranking records (leaf = SHA-256 of the record as JSON with sorted keys, leaves sorted by CVE id). Leaves are stored too, so a mismatch names the changed CVE.

`GET /api/aegis/integrity` recomputes the leaves from TigerData (or the bundled snapshot), re-hashes the files, fetches the transaction and compares the memo. It returns `verified`, `mismatch` (with `mismatched` CVE ids and a `reason`), `unverifiable` (Solana RPC unreachable; never reported as verified) or `unanchored`. The UI shows it on Vulnerability intelligence, in each CVE briefing and under Connections.

```sh
npm run solana:keygen          # creates .solana/devnet-keypair.json (gitignored) and prints the address
                               # devnet RPC airdrops are closed: fund the address at https://faucet.solana.com
npm run anchor:snapshot        # sends the memo and writes public/data/anchor.json (commit it)
node scripts/anchor-snapshot.mjs --dry-run   # recompute hashes only
```

Check it by hand: `git show HEAD:ml/top500.csv | sha256sum` equals `manifest.files["ml/top500.csv"].lf`; `node scripts/anchor-snapshot.mjs --dry-run` recomputes the manifest hash, which must equal the hash in the memo; open the explorer link for `anchors[0].signature`.

Limits:
- The anchor proves the files existed in this form **from the anchor time** (Nov 8, 2026). It does not prove they predate the Nov 4 label date; the Git history and the Devpost submission time are the evidence for that.
- Whoever holds the signing key can anchor a new manifest. Every anchor stays public on-chain and `anchors` in Git is append-only, so a later re-anchor is visible; the UI shows the first anchor time.
- Rerunning `prepare-data.py` changes the records, so re-anchor afterwards (a new entry is appended).
- Devnet is for the demo and has been reset in the past. Mainnet is the production path at a fraction of a cent per transaction (set `SOLANA_CLUSTER=mainnet-beta` and a funded key).
- Defense-plan approvals are not anchored yet. The next step is hash-chaining `aegis_app.events` and anchoring the chain head.
