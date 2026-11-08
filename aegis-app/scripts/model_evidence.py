"""Attach checked-in validation evidence and optional ML-generated explanations."""
import csv, json, math, re

def load_predictions(root):
    path = root / 'ml/outputs/predictions.parquet'
    exported = root / 'ml/outputs/app-predictions.json'
    if path.exists():
        try:
            import pandas as pd
        except ImportError as exc:
            raise RuntimeError('Reading predictions.parquet requires pandas and a parquet engine.') from exc
        return pd.read_parquet(path).to_dict('records'), 'ml/outputs/predictions.parquet'
    if exported.exists():
        return json.loads(exported.read_text()), 'TigerData cve_predictions export'
    return [], None

def load_bands(root):
    return list(csv.DictReader((root/'ml/outputs/rank_bands.csv').open()))

# Baselines the track README scores us against, in the order the pitch quotes them.
BASELINES = [('CVSS first','cvss_first'), ('EPSS first','epss_first'), ('Exploit code, then EPSS','exploit_then_epss')]

def validation_summary(root, total):
    """Headline validation numbers, read from the ML artifacts so the UI never hardcodes a score."""
    bands = load_bands(root)
    metrics = json.loads((root/'ml/outputs/metrics.json').read_text())['results']
    check = json.loads((root/'ml/outputs/check_2026.json').read_text())
    # Out-of-time folds V1 (2025-01..04) and V2 (2025-05..09), each scored at the scoreboard's depth.
    def folds_2025(key):
        return sum(v for k,v in metrics[key].items() if k.startswith(('V1@','V2@')))
    positives_2026 = {check[key]['positives'] for _,key in BASELINES}
    if len(positives_2026) != 1:
        raise ValueError('Baselines disagree on the number of 2026 exploited CVEs')
    summary = {
        'universe': total, 'depth': 500,
        'scoreboard2026': {
            'positives': positives_2026.pop(),
            'model': check['submitted_top500']['hits@500'],
            'baselines': [{'name':name,'hits':check[key]['hits@500']} for name,key in BASELINES],
        },
        'folds2025': {
            # rank_bands.csv partitions the whole 2025 validation set, so its hits sum to the positives.
            'positives': sum(int(b['valid_hits']) for b in bands),
            'model': folds_2025('model_selected'),
            'baseline': folds_2025('exploit_then_epss'),
            'baselineName': 'Exploit code, then EPSS',
        },
        'bands': [{'band':b['band'],'hits':int(b['valid_hits']),'count':int(b['valid_n']),
                   'rate':float(b['valid_rate']),'lift':float(b['lift'])} for b in bands],
    }
    s = summary['scoreboard2026']
    if not 0 < s['model'] <= s['positives'] or any(not 0 <= b['hits'] <= s['positives'] for b in s['baselines']):
        raise ValueError('2026 hit counts are outside the number of exploited CVEs')
    f = summary['folds2025']
    if not 0 < f['model'] <= f['positives'] or not 0 <= f['baseline'] <= f['positives']:
        raise ValueError('2025 fold hit counts are outside the number of exploited CVEs')
    return summary

def attach_evidence(items, root, total):
    bands = load_bands(root)
    predictions, source = load_predictions(root)
    prediction_map = {r['cve_id']:r for r in predictions}
    for item in items.values():
        band = next(b for b in bands if item['rank']/total <= float(b['hi']))
        n, hits = int(band['valid_n']), int(band['valid_hits'])
        rate = float(band['valid_rate'])
        assert n > 0 and 0 <= hits <= n and abs(rate-hits/n)<1e-8
        confidence = (f"Ranked #{item['rank']:,} of {total:,} ({band['band']}). In 2025 validation, "
                      f"{hits} of {n:,} CVEs ranked in this band ({rate:.2%}) were later exploited, "
                      f"{float(band['lift']):.1f}x the average.")
        evidence = {'status':'validation-only','source':'ml/outputs/rank_bands.csv',
                    'confidence':confidence,'reasons':[], 'nearest':None,
                    'validation':{'year':2025,'band':band['band'],'hits':hits,'count':n,'rate':rate,'lift':float(band['lift'])},
                    'universe':total}
        row = prediction_map.get(item['id'])
        if row is not None:
            if int(row['rank']) != item['rank']:
                raise ValueError(f"Model rank mismatch for {item['id']}; refusing mismatched evidence")
            reasons = row.get('reasons',[])
            if isinstance(reasons,str): reasons=json.loads(reasons)
            if not isinstance(reasons,list) or len(reasons)!=3 or not all(isinstance(r,str) and re.search(r'\d',r) for r in reasons):
                raise ValueError(f"Expected 3 numeric ML reasons for {item['id']}")
            if not isinstance(row.get('confidence'),str) or '2025 validation' not in row['confidence']:
                raise ValueError(f"Missing updated confidence for {item['id']}")
            evidence.update(status='complete',source=source,reasons=reasons,confidence=row['confidence'])
            cve,sim=row.get('nearest_kev_cve'),row.get('nearest_kev_sim')
            if isinstance(cve,str) and re.fullmatch(r'CVE-\d{4}-\d+',cve) and isinstance(sim,(int,float)) and math.isfinite(sim):
                evidence['nearest']={'id':cve,'product':str(row.get('nearest_kev_product') or ''),'similarity':float(sim),'historyCutoff':'2025-12-31'}
        item['modelEvidence']=evidence
    return sum(i['modelEvidence']['status']=='complete' for i in items.values())
