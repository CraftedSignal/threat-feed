---
title: Authenticated SQL Injection in ISPConfig Remote API
slug: 2026-08-ispconfig-sqli
description: An authenticated SQL injection vulnerability in the ISPConfig Remote API allows low-privilege users to execute arbitrary queries, leading to unauthorized data exfiltration and cross-tenant record manipulation.
date: "2026-08-19T20:39:29Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - ISPConfig
products:
  - ISPConfig
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ISPConfig contains an authenticated SQL injection vulnerability in the Remote API.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
    evidence: A remote API user holding any single low-privilege function permission can inject arbitrary SQL to delete or modify records across all tenants.
    confidence_band: high
cves:
  - id: CVE-2026-61518
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61518
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review and restrict API permissions for all active Remote API user accounts.
      owner: IT Operations
      due: 24h
      evidence: A remote API user holding any single low-privilege function permission can inject arbitrary SQL.
  mitigation_plan:
    - priority: immediate
      action: Patch ISPConfig to the version addressing CVE-2026-61518.
      owner: IT Operations
      addresses: CVE-2026-61518
      evidence: NVD vulnerability documentation.
---

ISPConfig (CVE-2026-61518) contains a critical authenticated SQL injection vulnerability within its Remote API. The vulnerability stems from improper handling of the 'primary_id' parameter used in 'delete' and 'update' API methods. Specifically, the application concatenates this user-supplied input directly into SQL WHERE clauses without implementing integer casting or parameterized query binding. The product's internal SQL injection scanner fails to validate quote-free boolean payloads by default, allowing attackers to bypass existing protections. An attacker with access to an account possessing even minimal API permissions can leverage this flaw to perform blind boolean inference, enabling the exfiltration of sensitive information, such as password hashes, or the unauthorized deletion and modification of database records across all managed tenants.

## Impact

Successful exploitation allows a low-privilege authenticated user to compromise the integrity and confidentiality of the entire ISPConfig database. This includes unauthorized access to client records and administrative credentials across all tenants. Given the control panel's role in managing hosting infrastructure, the ability to manipulate database entries represents a significant risk to the security of all downstream sites and services managed by the ISPConfig instance.

## Recommendation

- Upgrade ISPConfig installations to the version containing the security patch for CVE-2026-61518 as soon as it is released by the vendor.
- Review all user permissions assigned to Remote API accounts and enforce the principle of least privilege to ensure users only have access to necessary API methods.
- Enable and strictly configure WAF rules to inspect API requests for SQL injection patterns, specifically targeting boolean-based payloads in the 'primary_id' field.
- Audit database and API access logs for anomalous patterns such as unexpected boolean variations or high volumes of requests targeting 'delete' or 'update' methods from low-privilege accounts.
