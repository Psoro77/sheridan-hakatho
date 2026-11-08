import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';

export const appRoot = fileURLToPath(new URL('../', import.meta.url));
export function loadConfig() {
  const envFile = new URL('../.env.local', import.meta.url);
  const local = existsSync(envFile) ? parseEnv(readFileSync(envFile,'utf8')) : {};
  const env = { ...process.env, ...local };
  let databaseUrl = env.TIGERDATA_URL || '';
  if (!databaseUrl) {
    const credentialPath = env.TIGERDATA_CREDENTIALS_FILE || fileURLToPath(new URL('../../tiger-cloud-db-11853-credentials.txt', import.meta.url));
    if (existsSync(credentialPath)) {
      const text = readFileSync(credentialPath, 'utf8');
      databaseUrl = text.match(/postgres(?:ql)?:\/\/[^\s"'<>]+/)?.[0] || '';
    }
  }
  return {
    databaseUrl,
    graniteProvider: env.GRANITE_PROVIDER || 'huggingface',
    ollamaUrl: env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434',
    ollamaModel: env.OLLAMA_MODEL || 'granite4:latest',
    hfToken: env.HF_TOKEN || env.HUGGINGFACEHUB_API_TOKEN || '',
    hfEndpoint: env.HF_ENDPOINT_URL || '',
    hfModel: env.HF_MODEL_ID || 'ibm-granite/granite-4.2-8b:deepinfra',
    hfMode: env.HF_API_MODE || 'chat',
    apiKey: env.BREACHLIGHT_API_KEY || '',
    host: env.BREACHLIGHT_API_HOST || '127.0.0.1',
    port: Number(env.BREACHLIGHT_API_PORT || 5174),
    workspaceId: env.BREACHLIGHT_WORKSPACE_ID || 'sheridan-labs',
    solanaCluster: env.SOLANA_CLUSTER || 'devnet',
    solanaRpcUrl: env.SOLANA_RPC_URL || '',
    solanaKeypairPath: env.SOLANA_KEYPAIR_PATH || fileURLToPath(new URL('../.solana/devnet-keypair.json', import.meta.url)),
    // Ticketing: GitHub Issues or Jira Cloud. TICKET_PROVIDER picks one when both are set.
    ticketProvider: (env.TICKET_PROVIDER || '').toLowerCase(),
    ticketIncludeAssetNames: /^(1|true|yes)$/i.test(env.TICKET_INCLUDE_ASSET_NAMES || ''),
    githubToken: env.GITHUB_TOKEN || '',
    githubRepo: env.GITHUB_REPO || '',
    githubApiUrl: env.GITHUB_API_URL || 'https://api.github.com',
    jiraBaseUrl: env.JIRA_BASE_URL || '',
    jiraEmail: env.JIRA_EMAIL || '',
    jiraToken: env.JIRA_API_TOKEN || '',
    jiraProject: env.JIRA_PROJECT_KEY || '',
    jiraIssueType: env.JIRA_ISSUE_TYPE || 'Task',
  };
}
