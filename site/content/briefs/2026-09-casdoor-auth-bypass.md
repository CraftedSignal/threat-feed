---
title: Authorization Bypass Vulnerability in Casdoor /api/mcp Endpoint
slug: 2026-09-casdoor-auth-bypass
description: Casdoor versions through 4.4.0 contain an authorization bypass vulnerability (CVE-2026-91998) in the /api/mcp endpoint, allowing authenticated attackers to perform unauthorized administrative actions across all organizations.
date: "2026-09-15T13:40:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:casdoor:casdoor:*:*:*:*:*:*:*:*
vendors:
  - Casdoor
products:
  - Casdoor (<= 4.4.0)
cves:
  - id: CVE-2026-91998
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91998
rules:
  - title: Detect CVE-2026-91998 Exploitation - Unauthorized /api/mcp Access
    description: Detects potential exploitation of CVE-2026-91998 by identifying administrative requests to the /api/mcp endpoint that deviate from expected application scope.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Casdoor to a version containing the fix for CVE-2026-91998
      owner: IT Operations
      due: 24h
      evidence: Source advisory states CVE-2026-91998 affects Casdoor through 4.4.0
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the /api/mcp endpoint via network policy or WAF rules
      owner: IT Operations
      addresses: CVE-2026-91998
---

Casdoor versions up to and including 4.4.0 are affected by a severe authorization bypass vulnerability (CVE-2026-91998) located within the /api/mcp endpoint. This vulnerability allows an attacker who possesses valid credentials (clientId and clientSecret) for any single application registered within the Casdoor instance to gain elevated administrative privileges. 

By exploiting this flaw, an attacker can bypass scope restrictions and access administrative functions across all organizations managed by the Casdoor instance. This includes the ability to enumerate sensitive user records, such as email addresses and password salts, as well as the capability to create, modify, or delete administrator accounts. Because this exploit allows for arbitrary account manipulation, it poses a significant risk to the integrity of identity management systems using Casdoor. Defenders should prioritize patching or restricting access to the affected endpoint until an update is applied.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.9. Successful exploitation allows for full administrative control over the Casdoor identity management environment. An attacker can gain unauthorized access to all user information, perform account takeover by modifying credentials, or delete existing users, potentially leading to widespread service disruption or credential theft across all connected organizations.

## Recommendation

* Immediately upgrade Casdoor to a version patched against CVE-2026-91998.
* Audit access logs for the /api/mcp endpoint to identify requests originating from unauthorized clientId/clientSecret combinations or requests targeting organizations outside the scope of the authenticated client.
* Monitor for suspicious administrative account creation or modification events occurring across all organizations simultaneously.
