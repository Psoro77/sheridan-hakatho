# \[IBM\] Before the Breach

IBM Track · Sheridan Datathon 2026 · November 7-8 · Sheridan College, Hazel McCallion Campus

IBM's clients run thousands of applications, and thousands of new software vulnerabilities are published every week. Fewer than 1 in 250 is ever confirmed to be used by attackers. Security teams can't fix everything, so the question IBM hears from clients is always the same: what do we fix first?

IBM builds tools for this, like IBM Concert Protect for prioritizing vulnerabilities and IBM X-Force for threat intelligence. Your challenge is the one they face: using real vulnerability data, predict which vulnerabilities attackers will exploit, and show engineers what to fix first and why.

## The problem

92,205 vulnerabilities have been published so far in 2026, more than double all of 2024\. Each has an ID called a CVE, for example `CVE-2024-3400`. No team can fix them all, so most rank them by severity score (CVSS). But severity says how bad an attack could be, not whether anyone will attack.

The answer key is CISA's Known Exploited Vulnerabilities list (KEV). CISA is the US Cybersecurity and Infrastructure Security Agency, and the list holds vulnerabilities with confirmed attacks.

## IBM technology

You must use at least one or more IBM technologies. Tools that fit this problem include:

- IBM Granite language and embedding models: [https\://huggingface.co/ibm-granite](https://huggingface.co/ibm-granite)  
- IBM Granite TimeSeries: [https\://huggingface.co/ibm-granite/granite-timeseries-ttm-r2](https://huggingface.co/ibm-granite/granite-timeseries-ttm-r2)  
- watsonx.ai and watsonx Orchestrate (need an IBM account): [https\://www\.ibm.com/watsonx](https://www.ibm.com/watsonx)  
- Red Hat AI Inference Server and vLLM: [https\://docs.vllm.ai](https://docs.vllm.ai)

## The benchmark

`scoreboard_2026.csv` lists 72,670 vulnerabilities published January to September 2026 that were not on the KEV list at the end of their `snapshot_month`. Some were added to the list later. Judges count vulnerabilities added to the list through November 4, 2026\.

If your project ranks vulnerabilities, rank these using only what was known at the end of each one's `snapshot_month`, and submit `top500.csv` with one column, `cve_id`. Judges will check how many were later exploited. For comparison, standard rankings find:

| Ranking | Found in the top 500 |
| :---- | :---- |
| Highest CVSS 3 score first | 7 |
| EPSS first (a score for the chance of attack in the next 30 days) | 6 |
| Public exploit code first, then EPSS | 8 |

## The data

Download `data.zip` and unzip it (about 850 MB). See `DATA_DICTIONARY.md` for every column.

| File | What it is | Rows |
| :---- | :---- | :---- |
| `vulnerabilities.csv` | Every vulnerability published by NIST since 1988: description, severity scores, attack details, weakness type, dates | 401,082 |
| `affected_products.csv` | Each product and version a vulnerability affects | 3,155,934 |
| `references.csv` | Links attached to each vulnerability, tagged as patch, exploit, advisory and so on | 1,360,487 |
| `known_exploited.csv` | The KEV list up to December 31, 2025, with the date each vulnerability was added | 1,484 |
| `exploit_signals_2024.csv`, `exploit_signals_2025.csv` | For each month of 2024 and 2025: each vulnerability's EPSS score, whether it was on the KEV list, and whether public exploit code existed | 6,463,734 (both) |
| `weakness_types.csv` | Names of weakness types (CWE), for example SQL injection | 1,374 |
| `scoreboard_2026.csv` | The benchmark vulnerabilities above, with their EPSS score and exploit flags at the end of `snapshot_month` | 72,670 |

Files join on `cve_id`. `weakness_types.csv` matches the `cwe_ids` column.

## Keep it fair

The NIST files are today's versions, so some details were filled in after attacks happened. For 2026 vulnerabilities, `nvd_status`, `n_affected_cpes`, `n_references`, blank severity scores, and links to news or threat reports in `references.csv` can give part of the answer away, because NIST reviews attacked vulnerabilities first. In your write-up, say which columns you used.

## What to submit

On Devpost: a 2 to 3 minute demo video, your code repo, a short write-up, links to any outside data you used, and your top 500 if your project ranks vulnerabilities.

## Judging

- Discovery (35%): what you found that others would miss.  
- Data Use (25%): how well you used and checked the data.  
- Communication (25%): how clearly you explain it.  
- Impact (15%): how useful it would be to a real security team.

## Good to know

- A vulnerability not on the KEV list may still have been attacked.  
- NIST has not reviewed 51,046 of the 92,205 vulnerabilities published in 2026, so most have no product list. Every vulnerability has a description.  
- 37,853 references link to IBM X-Force Exchange, IBM's threat intelligence site.

## Sources

NIST National Vulnerability Database (fkie-cad/nvd-json-data-feeds mirror, November 6, 2026). CISA KEV list (up to December 31, 2025). EPSS scores from FIRST and public exploit flags (Exploit-DB, Metasploit, Nuclei, GitHub) from the t0sche/cvss-bt monthly history. MITRE CWE list, version 4.14.