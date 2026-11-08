import pg from 'pg';
export function makePool(config) {
  if (!config.databaseUrl) return null;
  const url = new URL(config.databaseUrl);
  for (const key of ['sslmode', 'sslcert', 'sslkey', 'sslrootcert']) url.searchParams.delete(key);
  const pool = new pg.Pool({ connectionString: url.toString(), ssl: { rejectUnauthorized: true }, max: 5, connectionTimeoutMillis: 8000, idleTimeoutMillis: 30000, statement_timeout: 10000, application_name: 'breachlight-defense' });
  pool.on('error', () => console.error('TigerData background connection failed; retrying on next request.'));
  return pool;
}
export async function inspectDatabase(pool) {
  const result = await pool.query("SELECT version(), current_database() as database, (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) as tls");
  const schemas = await pool.query("SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') AND table_type='BASE TABLE' ORDER BY table_schema,table_name LIMIT 50");
  return { connected:true, tls:result.rows[0].tls, tables:schemas.rows };
}
