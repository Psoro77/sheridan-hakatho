import { readFileSync } from 'node:fs';
import { loadConfig } from '../server/config.mjs';
import { makePool } from '../server/database.mjs';
const pool = makePool(loadConfig());
if (!pool) throw new Error('TigerData is not configured.');
const data=JSON.parse(readFileSync(new URL('../public/data/intelligence.json',import.meta.url),'utf8'));
let client;
try {
 client=await pool.connect();
 await client.query('BEGIN');
 await client.query(readFileSync(new URL('../server/schema.sql',import.meta.url),'utf8'));
 await client.query(`INSERT INTO breachlight_app.vulnerabilities(cve_id,model_rank,snapshot_month,record)
 SELECT x->>'id',(x->>'rank')::int,x->>'snapshot',x FROM jsonb_array_elements($1::jsonb) x
 ON CONFLICT(cve_id) DO UPDATE SET model_rank=EXCLUDED.model_rank,snapshot_month=EXCLUDED.snapshot_month,record=EXCLUDED.record,updated_at=now()`,[JSON.stringify(data.vulnerabilities)]);
 await client.query(`INSERT INTO breachlight_app.snapshot_months(month,total,selected)
 SELECT x->>'month',(x->>'count')::int,(x->>'selected')::int FROM jsonb_array_elements($1::jsonb) x
 ON CONFLICT(month) DO UPDATE SET total=EXCLUDED.total,selected=EXCLUDED.selected`,[JSON.stringify(data.months)]);
 const meta=Object.entries({source:data.source,validation:data.validation}).filter(([,value])=>value!==undefined);
 // Remove metadata keys the snapshot no longer carries (e.g. the retired 'metrics' key).
 await client.query('DELETE FROM breachlight_app.metadata WHERE NOT (key = ANY($1))',[meta.map(([key])=>key)]);
 for (const [key,value] of meta) {
  await client.query('INSERT INTO breachlight_app.metadata(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value',[key,JSON.stringify(value)]);
 }
 await client.query('COMMIT');
 const counts=await client.query('SELECT (SELECT count(*) FROM breachlight_app.vulnerabilities)::int as vulnerabilities, (SELECT sum(total) FROM breachlight_app.snapshot_months)::int as scoreboard_total');
 console.log('TigerData import complete:',JSON.stringify(counts.rows[0]));
} catch(e) {if(client)await client.query('ROLLBACK').catch(()=>{});console.error('TigerData import failed:',e.code||e.name);process.exitCode=1;} finally {client?.release();await pool.end();}
