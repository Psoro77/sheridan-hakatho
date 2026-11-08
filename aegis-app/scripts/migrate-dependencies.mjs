import { readFileSync } from 'node:fs';
import { makePool } from '../server/database.mjs';
import { loadConfig } from '../server/config.mjs';
const pool=makePool(loadConfig());try{await pool.query(readFileSync(new URL('../server/dependency-schema.sql',import.meta.url),'utf8'));console.log('Dependency scan and briefing tables are ready. Existing data preserved.');}catch(e){console.error('Migration failed:',e.code||e.name);process.exitCode=1}finally{await pool?.end()}
