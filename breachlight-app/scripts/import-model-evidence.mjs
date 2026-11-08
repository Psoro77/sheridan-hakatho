// Read only public model output fields, never credentials or database configuration.
import {writeFileSync} from 'node:fs';
import {loadConfig} from '../server/config.mjs';
import {makePool} from '../server/database.mjs';
const pool=makePool(loadConfig());
try{
 const exists=await pool.query("SELECT to_regclass('public.cve_predictions') AS name");
 if(!exists.rows[0].name)throw Object.assign(new Error(),{code:'ML_EXPORT_NOT_AVAILABLE'});
 const {rows}=await pool.query('SELECT cve_id,rank,reasons,confidence,nearest_kev_cve,nearest_kev_product,nearest_kev_sim FROM public.cve_predictions WHERE rank<=500 ORDER BY rank');
 if(rows.length!==500)throw Object.assign(new Error(),{code:'EXPECTED_500_PREDICTIONS'});
 writeFileSync(new URL('../../ml/outputs/app-predictions.json',import.meta.url),JSON.stringify(rows));
 console.log('Imported 500 model evidence records. Run python3 scripts/prepare-data.py, then npm run db:seed.');
}catch(e){console.error('Model evidence import:',e.code||e.name);process.exitCode=1}finally{await pool?.end()}
