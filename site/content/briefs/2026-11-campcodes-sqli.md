---
brief_id: brief-2026-11-05-campcodes-sqli
event_id: brief-2026-11-05-campcodes-sqli
revision: 1
activity_at: "2026-11-05T00:07:56Z"
title: 'Campcodes Division Regional Athletic Meet Game Result Matrix System: SQL injection (CVE-2026-122048)'
slug: 2026-11-campcodes-sqli
description: A SQL injection vulnerability in the Division Regional Athletic Meet Game Result Matrix System allows remote attackers to execute arbitrary database commands via the abbr parameter in check-user.php.
date: "2026-11-05T00:07:56Z"
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
cpes:
  - cpe:2.3:a:campcodes:division_regional_athletic_meet_game_result_matrix_system:*:*:*:*:*:*:*:*
vendors:
  - Campcodes
products:
  - Division Regional Athletic Meet Game Result Matrix System (<= 2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Such manipulation of the argument abbr leads to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-122048
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122048
rules:
  - title: Detect CVE-2026-122048 Exploitation - SQL Injection in check-user.php
    description: Detects exploitation attempts targeting the abbr parameter in check-user.php using common SQL injection syntax.
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
    - action: Patch or restrict access to /dipam/check-user.php
      owner: IT Operations
      due: 24h
      evidence: Vulnerability in file /dipam/check-user.php
  hunt_leads:
    - lead: Inspect web server logs for requests to check-user.php containing SQL keywords or character sequences (e.g., --, OR 1=1)
      technique_id: T1190
      data_needed:
        - web_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit is publicly available and might be used.
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to filter malicious payloads in the abbr parameter
      owner: SOC
      addresses: CVE-2026-122048
      evidence: SQL injection via abbr argument
---

A SQL injection vulnerability (CVE-2026-122048) exists in Campcodes Division Regional Athletic Meet Game Result Matrix System versions 2.1 and earlier. The vulnerability is located in the /dipam/check-user.php script. An attacker can manipulate the abbr parameter to inject malicious SQL commands, enabling unauthorized database access. Exploitation is possible remotely and functional exploit code is publicly available.

## Impact

Successful exploitation allows for unauthorized database interaction, which may lead to data exfiltration, modification, or destruction depending on the database user permissions.

## Recommendation

- Inventory all instances of the Campcodes Division Regional Athletic Meet Game Result Matrix System to identify versions 2.1 and earlier.
- Apply the vendor-provided patch if available, or restrict access to the /dipam/ directory.
- Monitor web server access logs for anomalous payloads in the 'abbr' parameter of 'check-user.php' requests.
