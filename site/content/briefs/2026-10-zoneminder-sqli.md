---
brief_id: brief-2026-10-24-zoneminder-sqli
event_id: brief-2026-10-24-zoneminder-sqli
revision: 1
activity_at: "2026-10-24T04:05:34Z"
title: 'ZoneMinder: Authenticated SQL Injection in event management (CVE-2024-51482)'
slug: 2026-10-zoneminder-sqli
description: An authenticated time-based blind SQL injection vulnerability in ZoneMinder versions up to 1.37.64 allows attackers to exfiltrate sensitive database information via the removetag action.
date: "2026-10-24T04:05:34Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs internal lab validation
cpes:
  - cpe:2.3:a:zoneminder:zoneminder:*:*:*:*:*:*:*:*
vendors:
  - ZoneMinder
products:
  - ZoneMinder (<= 1.37.64)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated time-based blind SQLi in ZoneMinder up to 1.37.64 via event management.
    confidence_band: high
cves:
  - id: CVE-2024-51482
    cvss: 9.9
    epss: 0.3661
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-PLUR1BU5-CVE-2024-51482-POC
  - https://github.com/ZoneMinder/zoneminder
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-PLUR1BU5-CVE-2024-51482-POC&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2024-51482 Exploitation - SQL Injection in removetag
    description: Detects exploitation attempts against CVE-2024-51482 by identifying HTTP requests to the removetag action containing potential SQL injection patterns within the tid parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch ZoneMinder to 1.37.65
      owner: IT Operations
      due: 48h
      evidence: 'Fixed In: v1.37.65'
  enrichment_needed:
    - item: Internal instance inventory
      owner: IT Operations
      reason: Identify exposure of ZoneMinder instances
      evidence: 'Affected Versions: ZoneMinder v1.37.* <= 1.37.64'
  hunt_leads:
    - lead: Identify authenticated sessions with unusual sleep-like timing patterns or repeated POST requests to index.php
      technique_id: T1190
      data_needed:
        - Web server response time logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The exploit uses conditional SLEEP queries to extract data.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 1.37.65
      owner: IT Operations
      addresses: CVE-2024-51482
      evidence: Source states vulnerability fixed in v1.37.65
  gaps:
    - Lack of dedicated WAF signature for this specific injection path
---

CVE-2024-51482 is a time-based blind SQL injection vulnerability affecting ZoneMinder versions through 1.37.64. The flaw exists within the event management functionality of the application. An authenticated attacker can trigger this vulnerability by sending specially crafted requests to the `/zm/index.php` endpoint, specifically targeting the `removetag` action and the `tid` parameter. The vulnerability enables attackers to extract data from the backend database using conditional `SLEEP` payloads.

## Impact

Successful exploitation allows authenticated attackers to perform database enumeration and dump sensitive information, including user credentials stored in the `zm.Users` table. The CVSS score for this vulnerability is 9.9.

## Recommendation

* Upgrade ZoneMinder to version 1.37.65 or later immediately to patch the vulnerability.
* Audit access logs for authenticated users performing frequent or anomalous POST requests to `/zm/index.php` with the `action=removetag` parameter.
* Restrict access to the ZoneMinder interface to trusted networks only.
