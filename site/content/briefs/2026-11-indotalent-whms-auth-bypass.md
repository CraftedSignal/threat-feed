---
brief_id: brief-2026-11-10-indotalent-whms-auth-bypass
event_id: brief-2026-11-10-indotalent-whms-auth-bypass
revision: 1
activity_at: "2026-11-10T04:01:51Z"
title: INDOTALENT Asp.Net-Core-Inventory-Order-Management-System authentication bypass (CVE-2026-125383)
slug: 2026-11-indotalent-whms-auth-bypass
description: INDOTALENT WHMS versions before 10.20261109 contain an authentication bypass vulnerability via hard-coded JWT secrets in appsettings.json, allowing remote unauthenticated attackers to forge administrative tokens.
date: "2026-11-10T04:01:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:a:indotalent:asp.net-core-inventory-order-management-system:*:*:*:*:*:*:*:*
vendors:
  - INDOTALENT
products:
  - Asp.Net-Core-Inventory-Order-Management-System (< 10.20261109)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated remote attackers can forge tokens for any user ID and role that the Tokens/DI.cs validator trusts, gaining administrator access to the entire API.
    confidence_band: high
cves:
  - id: CVE-2026-125383
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125383
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Asp.Net-Core-Inventory-Order-Management-System to 10.20261109
      owner: IT Operations
      due: 24h
      evidence: Vulnerability fixed in 10.20261109
  hunt_leads:
    - lead: Inspect access logs for anomalous authentication patterns or administrative API calls originating from non-administrative IP addresses.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application API logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves forging administrative tokens to access the API.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 10.20261109 or rotate hard-coded keys in appsettings.json
      owner: IT Operations
      addresses: CVE-2026-125383
      evidence: Hard-coded secrets in configuration lead to auth bypass
---

INDOTALENT Asp.Net-Core-Inventory-Order-Management-System versions prior to 10.20261109 are vulnerable to authentication bypass due to the presence of hard-coded JWT signing keys, issuer, and audience strings within the 'appsettings.json' configuration file. An unauthenticated remote attacker can leverage these hard-coded values to generate valid, signed JWTs for any user account, including those with administrative privileges, to gain full control over the API.

## Impact

Successful exploitation results in full unauthenticated administrative access to the API and the underlying inventory and order management data.

## Recommendation

- Upgrade INDOTALENT Asp.Net-Core-Inventory-Order-Management-System to version 10.20261109 or later immediately.
- Review the contents of 'appsettings.json' in existing deployments to identify if hard-coded signing keys are present, especially if an immediate upgrade is not feasible.
- Rotate all JWT signing keys if the application has been exposed to the internet.
