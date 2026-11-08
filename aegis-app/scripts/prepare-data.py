"""Build a browser-safe snapshot from the checked-in ranking and local IBM data."""
import csv,json,pathlib,collections
from model_evidence import attach_evidence, validation_summary
root=pathlib.Path(__file__).resolve().parents[2]
out=root/'aegis-app/public/data';out.mkdir(parents=True,exist_ok=True)
def rows(name):
 with (root/'IBM/data'/name).open() as f: yield from csv.DictReader(f)
with (root/'ml/top500.csv').open() as f: ids=[r['cve_id'] for r in csv.DictReader(f)]
rank={id:i+1 for i,id in enumerate(ids)}
signals={r['cve_id']:r for r in rows('scoreboard_2026.csv')}
items={}
for r in rows('vulnerabilities.csv'):
 id=r['cve_id']
 if id not in rank:continue
 s=signals[id]
 items[id]={'id':id,'rank':rank[id],'description':r['description'],'published':r['published'],'snapshot':s['snapshot_month'],'cvss':float(r['cvss3_score']) if r['cvss3_score'] else None,'epss':float(s['epss']) if s['epss'] else None,'flags':[k for k in ['exploitdb','metasploit','nuclei','poc_github'] if s[k]=='1'],'products':[],'references':[],'attackVector':r['attack_vector'],'weakness':r['cwe_ids']}
for r in rows('affected_products.csv'):
 if r['cve_id'] in items:
  ps=items[r['cve_id']]['products']; p={'vendor':r['vendor'],'name':r['product']}
  if p not in ps and len(ps)<5: ps.append(p)
for r in rows('references.csv'):
 if r['cve_id'] in items and r['url'].startswith('https://'):
  rs=items[r['cve_id']]['references']
  if len(rs)<4:rs.append({'url':r['url'],'domain':r['domain'],'tags':r['tags']})
months=collections.Counter(s['snapshot_month'] for s in signals.values())
complete=attach_evidence(items,root,len(signals))
validation=validation_summary(root,len(signals))
assert len(items)==500 and len(set(ids))==500, 'Expected exactly 500 unique ranked CVEs'
print(f'Model evidence: {complete}/500 generated reasons; 500/500 validation evidence')
f=validation['folds2025']
print(f"Validation: 2025 folds {f['model']}/{f['positives']} vs baselines {[b['hits'] for b in f['baselines']]}")
result={'vulnerabilities':sorted(items.values(),key=lambda x:x['rank']),'months':[{'month':m,'count':n,'selected':sum(x['snapshot']==m for x in items.values())} for m,n in sorted(months.items())],'validation':validation,'source':'IBM datathon dataset · November 2026 snapshot'}
(out/'intelligence.json').write_text(json.dumps(result,separators=(',',':')))
print(f'Prepared {len(items)} real ranked CVEs; {len(signals)} scoreboard entries summarized')
