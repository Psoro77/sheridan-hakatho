import {loadConfig} from '../server/config.mjs';
import {makePool} from '../server/database.mjs';
const pool=makePool(loadConfig());
try{const r=await pool.query("SELECT table_schema,column_name FROM information_schema.columns WHERE table_name='cve_predictions' ORDER BY ordinal_position");console.log(JSON.stringify(r.rows));}catch(e){console.error(e.code||e.name);process.exitCode=1}finally{await pool?.end()}
