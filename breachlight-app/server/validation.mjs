import { z } from 'zod';
export const assetSchema=z.object({id:z.string().min(1).max(100),name:z.string().min(1).max(200),product:z.string().min(1).max(200),exposure:z.enum(['Public','Internal']),criticality:z.enum(['High','Medium','Low'])});
export const cveId=z.string().regex(/^CVE-\d{4}-\d{4,10}$/);
export const workspaceSchema=z.object({assets:z.array(assetSchema).min(1).max(1000),inventoryMode:z.enum(['Demo inventory','Uploaded inventory']),plan:z.array(cveId).max(500),done:z.array(cveId).max(500)}).refine(s=>new Set(s.assets.map(a=>a.id)).size===s.assets.length,'Asset IDs must be unique').refine(s=>new Set(s.plan).size===s.plan.length,'Plan IDs must be unique').refine(s=>s.done.every(id=>s.plan.includes(id)),'Reviewed items must belong to the plan');
export const explainSchema=z.object({cveId,assets:z.array(assetSchema).max(1000)});
export const saveSchema=z.object({state:workspaceSchema,revision:z.number().int().nonnegative()});
