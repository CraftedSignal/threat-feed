---
title: Unauthenticated SQL Injection in Fumasoft Fumeng Cloud
slug: 2026-09-fumasoft-sql-injection
description: Fumasoft Fumeng Cloud contains a critical SQL injection vulnerability in the AjaxMethod.ashx endpoint that allows unauthenticated remote attackers to execute arbitrary database queries.
date: "2026-09-29T16:28:14Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:fumasoft:fumeng_cloud:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - active-exploitation
vendors:
  - Fumasoft
products:
  - Fumeng Cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Fumasoft Fumeng Cloud contains a SQL injection vulnerability in the AjaxMethod.ashx endpoint that allows unauthenticated remote attackers to inject arbitrary SQL
    confidence_band: high
cves:
  - id: CVE-2023-54400
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54400
rules:
  - title: Detect CVE-2023-54400 Exploitation - SQL Injection in AjaxMethod.ashx
    description: Detects attempts to exploit CVE-2023-54400 by identifying SQL injection keywords in the Name parameter sent to the AjaxMethod.ashx endpoint.
    platform: sigma
    severity: critical
    tactics:
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule for AjaxMethod.ashx SQL injection
      owner: Detection Engineering
      due: 24h
      evidence: Active exploitation observed in the wild
  mitigation_plan:
    - priority: immediate
      action: Identify and patch all instances of Fumeng Cloud
      owner: IT Operations
      addresses: CVE-2023-54400
      evidence: NVD vulnerability disclosure
---

Fumasoft Fumeng Cloud is affected by a critical SQL injection vulnerability identified as CVE-2023-54400. The vulnerability exists within the AjaxMethod.ashx endpoint, specifically within the getEmpByname action. Unauthenticated remote attackers can inject arbitrary SQL commands through the Name parameter, which is processed by the underlying Microsoft SQL Server backend. Successful exploitation allows attackers to extract, disclose, or modify sensitive database contents. In advanced scenarios, this SQL injection can be leveraged to achieve remote code execution on the underlying host server. The Shadowserver Foundation reported observing exploitation of this vulnerability in the wild as early as October 18, 2023. Given the severity and the availability of proof-of-concept vectors, organizations using Fumeng Cloud should prioritize remediation.

## Impact

The vulnerability carries a CVSS v3.1 score of 9.8, indicating a critical severity. Exploitation results in the loss of confidentiality, integrity, and availability of data stored within the Fumeng Cloud database. If the database service account is running with elevated privileges, the impact extends to full server compromise, allowing attackers to pivot into the internal network or deploy further malicious payloads. 

## Recommendation

Prioritize patching of Fumasoft Fumeng Cloud installations. As the vulnerability is actively exploited in the wild, identify and monitor logs for anomalous HTTP POST requests to the AjaxMethod.ashx endpoint. 

- Audit web server logs for HTTP requests containing SQL syntax (e.g., UNION, SELECT, OR, 1=1) targeting the AjaxMethod.ashx endpoint.
- Implement strict input validation on the Name parameter for all API endpoints in Fumeng Cloud.
- Restrict access to the AjaxMethod.ashx endpoint to trusted IP addresses if immediate patching is not possible.
