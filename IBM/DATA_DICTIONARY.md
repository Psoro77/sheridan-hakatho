# Data dictionary

All files are in `data/`. They join on `cve_id` (the vulnerability's ID, for example `CVE-2024-3400`), except `weakness_types.csv`, which matches `cwe_ids`. Dates are YYYY-MM-DD. CISA is the US Cybersecurity and Infrastructure Security Agency. Files use standard CSV quoting; if a reader fails, set the quote and escape characters to `"`.

## Watch out for

- The NIST files (`vulnerabilities.csv`, `affected_products.csv`, `references.csv`) are today's versions. Details can be added after an attack, and `last_modified` is mid-2026 or later for every row. Links to the KEV list have been removed from `references.csv`.
- NIST reviews vulnerabilities on the KEV list first, and links to security-company research or news are often added after an attack. So for 2026, `nvd_status`, `n_affected_cpes`, blank scores and those links in `references.csv` can give much of the answer away.
- The year in a `cve_id` is when the ID was reserved, not always when it was published. Use `published`.
- `Received`, `Awaiting Analysis` and `Undergoing Analysis` mean NIST has not analysed it yet, so scores, weakness types and products can be blank. `Deferred` means NIST will not analyse it.
- EPSS changed its model in March 2025, so scores before and after are not directly comparable.
- February 2025 in `exploit_signals_2025.csv` is missing about 14,500 vulnerabilities. About 11,800 IDs in the signals files are not in `vulnerabilities.csv` (rejected IDs).
- KEV `date_added` is before `published` for 62 vulnerabilities.

## vulnerabilities.csv

One row per vulnerability, published 1988 to November 6, 2026 (401,082 rows).

| Column | Meaning |
|---|---|
| `cve_id` | Vulnerability ID |
| `published`, `last_modified` | Date NIST published it, and date it was last changed |
| `nvd_status` | NIST's analysis status: `Analyzed`, `Modified` (analysed, then changed), `Deferred`, `Awaiting Analysis`, `Undergoing Analysis`, `Received` |
| `assigner` | Who assigned the ID, usually the vendor's security team (an email or an ID) |
| `description` | What the vulnerability is, in English |
| `cvss3_version`, `cvss3_score`, `cvss3_severity`, `cvss3_vector` | CVSS (Common Vulnerability Scoring System) version 3 severity: score 0 to 10, `NONE` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`, and the vector string, a short code listing the parts below. NIST's own score is used when there is one |
| `attack_vector` | How an attacker reaches it: `NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL` |
| `attack_complexity` | `LOW` or `HIGH` |
| `privileges_required` | Access the attacker needs first: `NONE`, `LOW`, `HIGH` |
| `user_interaction` | Whether a user has to do something, like click a link: `NONE` or `REQUIRED` |
| `scope` | `CHANGED` if the attack can reach beyond the vulnerable component, otherwise `UNCHANGED` |
| `confidentiality_impact`, `integrity_impact`, `availability_impact` | Damage to data secrecy, data accuracy and uptime: `NONE`, `LOW`, `HIGH` |
| `cvss3_exploitability_score`, `cvss3_impact_score` | The two parts of the CVSS 3 score |
| `cvss3_source` | Who gave the CVSS 3 score: `nvd@nist.gov`, the vendor, or `134c704f-9b21-4f2e-91b3-4a467353bcc0` (CISA) |
| `cvss4_score`, `cvss4_severity`, `cvss4_vector` | CVSS version 4, used for newer vulnerabilities |
| `cvss2_score`, `cvss2_severity`, `cvss2_vector` | CVSS version 2, used for older vulnerabilities |
| `cwe_ids` | Weakness types, separated by `;`. Look them up in `weakness_types.csv` |
| `n_references` | Number of rows in `references.csv` |
| `n_affected_cpes` | Number of rows in `affected_products.csv` |

## affected_products.csv

One row per vulnerability and affected product or version range (3,155,934 rows). Read the version columns as text. Products use NIST's product naming (CPE, Common Platform Enumeration), in lower case with underscores, for example `microsoft`, `windows_11_23h2`.

| Column | Meaning |
|---|---|
| `cve_id` | Vulnerability ID |
| `type` | `application`, `operating_system` or `hardware` |
| `vendor`, `product` | Vendor and product |
| `version`, `update` | Exact version and update. Blank means a range or any version |
| `version_start_including`, `version_start_excluding`, `version_end_including`, `version_end_excluding` | The affected version range, when there is one |
| `vulnerable` | `Y` if this product is vulnerable. `N` means it is listed only because the vulnerable product must run on it (for example, an app that is only vulnerable on a certain operating system) |

## references.csv

One row per link attached to a vulnerability (1,360,487 rows).

| Column | Meaning |
|---|---|
| `cve_id` | Vulnerability ID |
| `url`, `domain` | The link and its website |
| `tags` | NIST's tags, separated by `;`: for example `Patch`, `Exploit`, `Vendor Advisory`, `Third Party Advisory`, `Mitigation`, `Broken Link` |

## known_exploited.csv

CISA's Known Exploited Vulnerabilities (KEV) catalog: vulnerabilities with confirmed attacks, added November 2021 to December 31, 2025 (1,484 rows).

| Column | Meaning |
|---|---|
| `cve_id` | Vulnerability ID |
| `vendor`, `product`, `name` | CISA's names for the vendor, product and vulnerability |
| `date_added` | Date CISA added it |
| `short_description` | CISA's description |
| `required_action`, `due_date` | What US federal agencies must do, and by when |
| `known_ransomware_use` | `Known` if it has been used in ransomware attacks, otherwise `Unknown` |
| `cwe_ids` | Weakness types, separated by `;` |

## exploit_signals_2024.csv, exploit_signals_2025.csv

What was known about each vulnerability at the end of each month, January 2024 to December 2025 (6,463,734 rows in total). Vulnerabilities with no EPSS score and no flags that month are left out.

| Column | Meaning |
|---|---|
| `month` | YYYY-MM. Values are from around the last day of that month |
| `cve_id` | Vulnerability ID |
| `epss` | EPSS score: the estimated chance, 0 to 1, that the vulnerability is attacked in the next 30 days. Blank if it had no score that month |
| `in_kev` | `1` if it was on the KEV list then |
| `exploitdb`, `metasploit`, `nuclei`, `poc_github` | `1` if public attack or detection code existed then: on Exploit-DB (a public archive of exploits), in Metasploit (a hacking toolkit), as a Nuclei template (a scanner check), or as a proof of concept (working demo code) on GitHub |

## weakness_types.csv

MITRE's list of weakness types (CWE), version 4.14 (1,374 rows).

| Column | Meaning |
|---|---|
| `cwe_id` | For example `CWE-79`. `NVD-CWE-Other` and `NVD-CWE-noinfo` are NIST placeholders. CWE-701, CWE-702 and CWE-1026 are used in the data but not listed |
| `name` | For example `Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')` |
| `kind` | `Weakness`, `Category` for a group of weaknesses, or `NVD` for the two NIST placeholders |
| `abstraction` | How specific it is: `Pillar` (broadest), `Class`, `Base`, `Variant` (most specific), or `Compound` (a combination). Blank for categories |
| `status` | MITRE's status for the entry |
| `description` | Short description |

## scoreboard_2026.csv

The benchmark: vulnerabilities published January to September 2026 that were not on the KEV list by the end of their `snapshot_month` (72,670 rows).

| Column | Meaning |
|---|---|
| `cve_id`, `published` | Vulnerability ID and publish date |
| `snapshot_month` | The month to predict from: the publish month, or July for June (June 2026 signals are missing) |
| `epss`, `exploitdb`, `metasploit`, `nuclei`, `poc_github` | EPSS score and exploit flags at the end of `snapshot_month`. Blank `epss` and `0` flags if there was no data |
