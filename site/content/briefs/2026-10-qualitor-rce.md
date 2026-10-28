---
brief_id: brief-2026-10-28-qualitor-rce
event_id: brief-2026-10-28-qualitor-rce
revision: 1
activity_at: "2026-10-28T09:57:28Z"
title: 'Qualitor: Unauthenticated Remote Code Execution (CVE-2023-47253)'
slug: 2026-10-qualitor-rce
description: Qualitor versions 8.20 and earlier are vulnerable to unauthenticated remote code execution via PHP code injection into the gridValoresPopHidden parameter, with public proof-of-concept exploits available.
date: "2026-10-28T09:57:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for production deployment pending environment validation.
cpes:
  - cpe:2.3:a:qualitor:qualitor:*:*:*:*:*:*:*:*
tags:
  - webserver
  - rce
  - php
  - cve-2023-47253
vendors:
  - Qualitor
products:
  - Qualitor (<= 8.20)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated RCE in Qualitor <= 8.20 via eval() on gridValoresPopHidden parameter.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: allows remote execution of PHP code, such as functions like system() and passthru().
    confidence_band: high
cves:
  - id: CVE-2023-47253
    cvss: 9.8
    epss: 0.14308
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OPENXP-RESEARCH-CVE-2023-47253
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-OPENXP-RESEARCH-CVE-2023-47253&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2023-47253 Exploitation - Unauthenticated RCE
    description: Detects exploitation attempts against Qualitor by monitoring HTTP requests containing the vulnerable gridValoresPopHidden parameter in the processVariavel.php script.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Scan network perimeter for Qualitor instances running version 8.20 or lower.
      owner: SOC
      due: 24h
      evidence: Vulnerability affects Qualitor <= 8.20.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to a version beyond 8.20 or disable the vulnerable script access if patching is not possible.
      owner: IT Operations
      addresses: CVE-2023-47253
      evidence: Qualitor <= 8.20 is affected.
---

Qualitor software (version 8.20 and earlier) contains a critical remote code execution (RCE) vulnerability identified as CVE-2023-47253. The vulnerability exists in the script '/html/ad/adpesquisasql/request/processVariavel.php', which passes user-controlled input from the 'gridValoresPopHidden' HTTP request parameter directly into a PHP eval() function. This allows an unauthenticated remote attacker to execute arbitrary PHP code on the underlying server.

## Impact
Successful exploitation allows an unauthenticated attacker to execute arbitrary system commands, leading to full system compromise, data theft, and loss of integrity and availability.

## Recommendation
- Update all Qualitor instances to a version later than 8.20 immediately.
- Review web server access logs for requests containing the 'gridValoresPopHidden' parameter targeting the '/html/ad/adpesquisasql/request/processVariavel.php' file.
- Inspect server filesystem for evidence of webshells or unauthorized modifications, particularly in the directory containing the vulnerable script.
