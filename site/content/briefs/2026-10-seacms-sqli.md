---
brief_id: brief-2026-10-22-seacms-sqli
event_id: brief-2026-10-22-seacms-sqli
revision: 1
activity_at: "2026-10-22T14:14:49Z"
title: 'SeaCMS: Unauthenticated SQL injection (CVE-2019-25778)'
slug: 2026-10-seacms-sqli
description: SeaCMS versions through 8.7 are vulnerable to unauthenticated remote SQL injection via the rlist[] parameter, enabling database information exfiltration through error-based exploitation.
date: "2026-10-22T14:14:49Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; detection rules require environment tuning.
cpes:
  - cpe:2.3:a:seacms:seacms:*:*:*:*:*:*:*:*
vendors:
  - SeaCMS
products:
  - SeaCMS (<= 8.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SeaCMS through 8.7 contains an unauthenticated SQL injection vulnerability that allows remote attackers to manipulate database queries.
    confidence_band: high
cves:
  - id: CVE-2019-25778
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25778
rules:
  - title: Detect CVE-2019-25778 Exploitation - SQL Injection in SeaCMS
    description: Detects exploitation attempts against SeaCMS by identifying suspicious characters and SQL functions within the rlist parameter of the index.php comment API.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch SeaCMS deployments to a version above 8.7.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions through 8.7.
  hunt_leads:
    - lead: Inspect web logs for attempts to access /comment/api/index.php containing SQL injection patterns.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation evidence was first observed in October 2023.
---

SeaCMS through version 8.7 contains an unauthenticated SQL injection vulnerability in the /comment/api/index.php endpoint. The flaw exists in the handling of the rlist[] array parameter, which allows an attacker to manipulate database queries. By injecting crafted values including backtick-quoted variables and the extractvalue function, attackers can force the application to return database content within error messages. Exploitation of this vulnerability has been observed in the wild since October 2023.

## Impact

Successful exploitation allows for the unauthorized extraction of database information through error-based techniques, potentially leading to full database compromise or information disclosure.

## Recommendation

* Identify and audit all deployments of SeaCMS in the environment to determine if versions 8.7 or older are in use.
* Upgrade to the latest version of SeaCMS that remediates CVE-2019-25778.
* Implement WAF rules to inspect HTTP GET requests to /comment/api/index.php and block or log requests containing SQL metacharacters or function calls (e.g., extractvalue, backticks) within the rlist[] parameter.
