---
title: Supply Chain Compromise of Rank Math SEO PRO WordPress Plugin
slug: 2026-10-rank-math-supply-chain
description: A supply-chain compromise of Rank Math SEO PRO version 3.0.123, distributed between October 15 and 16, 2026, introduced a backdoor enabling persistent access, credential theft, and unauthorized administrative control.
date: "2026-10-19T18:08:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:rankmath:seo_pro:3.0.123:*:*:*:*:wordpress:*:*
tags:
  - supply-chain
  - wordpress
  - cve-2026-111862
  - backdoor
vendors:
  - Rank Math
products:
  - Rank Math SEO PRO (version 3.0.123)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Supply Chain Compromise
    evidence: Rank Math SEO PRO for WordPress is affected by a supply-chain compromise in a subset of version 3.0.123 packages.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The malware may establish persistent access, communicate with rank1cdn[.]com, recreate hidden backdoors on page visits.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1136
    technique_name: Create Account
    evidence: Rank Math identifies three malicious wp_options keys, hidden PHP backdoors, unauthorized administrator accounts, a fake WordPress core file, PHP-executable .cache files, and a system cron marker as incident indicators.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The malware may establish persistent access, communicate with rank1cdn[.]com, recreate hidden backdoors on page visits.
    confidence_band: high
cves:
  - id: CVE-2026-111862
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111862
iocs:
  - type: domain
    value: rank1cdn.com
ioc_counts:
  domain: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade to Rank Math SEO PRO 3.0.124
      owner: IT Operations
      due: 24h
      evidence: Rank Math removed the affected files and released version 3.0.124 as the clean replacement.
    - action: Block rank1cdn.com
      owner: SOC
      due: 1h
      evidence: Malicious C2 domain.
  hunt_leads:
    - lead: Search for unexpected .cache files containing PHP tags or execution patterns.
      technique_id: T1547.006
      data_needed:
        - File system auditing
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rank Math identifies... PHP-executable .cache files... as incident indicators.
  mitigation_plan:
    - priority: immediate
      action: Rotate all credentials accessible to the compromised WordPress server.
      owner: IT Operations
      addresses: CVE-2026-111862
      evidence: The malware may... expose WordPress credentials, database credentials, API keys, and other secrets.
---

A supply-chain compromise affected Rank Math SEO PRO version 3.0.123 for WordPress. Packages downloaded or updated between October 15, 2026 (20:02 UTC) and October 16, 2026 (07:12 UTC) were found to contain malicious code. The compromise allows attackers to establish persistent access, exfiltrate sensitive site secrets, and manipulate site configuration.

Defenders must identify the presence of unauthorized administrative accounts, malicious files within the WordPress core, PHP-executable files within cache directories, and specific entries within the WordPress options table. Rank Math has released version 3.0.124 as a clean replacement. Organizations that deployed the affected package during the specified window are advised to treat the underlying server and WordPress environment as fully compromised.

## Attack Chain

1. Attacker gains unauthorized access to the distribution channel and injects malicious code into the Rank Math SEO PRO 3.0.123 plugin package.
2. The malicious package is downloaded or updated onto target WordPress installations via the standard plugin management interface.
3. Malware activates upon plugin initialization and execution within the web server environment.
4. The malware creates hidden PHP backdoors and modifies WordPress core files to ensure persistence.
5. The payload establishes communication with the C2 domain rank1cdn[.]com for instructions.
6. The malware harvests WordPress credentials, database credentials, and API keys stored in the web server environment.
7. The malware creates unauthorized administrative accounts or adds malicious keys to the 'wp_options' table to maintain control.
8. The attacker executes arbitrary commands and exfiltrates data from the compromised environment.

## Impact

The compromise provides attackers with full administrative control over affected WordPress sites. Impacted organizations are at risk of data exfiltration (including database contents and configuration secrets), unauthorized site modifications, and persistent unauthorized access. Sites that activated the affected package are considered fully compromised, necessitating a complete forensic audit and security credential rotation.

## Recommendation

* Identify any WordPress site that installed or updated the Rank Math SEO PRO plugin during the window of October 15, 2026 (20:02 UTC) through October 16, 2026 (07:12 UTC).
* Upgrade to Rank Math SEO PRO version 3.0.124 or later immediately.
* Search for unauthorized administrative users in the WordPress database and audit the `wp_options` table for unexpected keys associated with the plugin incident.
* Scan file systems for hidden PHP backdoors, fake WordPress core files, and files with a `.cache` extension that contain PHP code.
* Block traffic to `rank1cdn.com` at the network perimeter (firewall/DNS).
* Rotate all credentials accessible to the web server, including database passwords, WordPress admin accounts, and API keys.
