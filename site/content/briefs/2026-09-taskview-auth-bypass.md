---
title: Unauthenticated Account Takeover in Taskview Community via OAuth Dynamic Registration
slug: 2026-09-taskview-auth-bypass
description: Taskview Community versions before 1.56.0 are vulnerable to an authentication bypass in the OAuth 2.0 Dynamic Client Registration endpoint, allowing unauthenticated attackers to register clients and hijack user accounts.
date: "2026-09-24T20:47:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:taskview:taskview_community:*:*:*:*:*:*:*:*
vendors:
  - Taskview
products:
  - Taskview Community (< 1.56.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1185
    technique_name: Browser Session Hijacking
    evidence: Attackers can send a POST request to the registration endpoint to obtain a client_id and client_secret, then craft a malicious authorization link pointing to an attacker-controlled redirect URI to capture authorization codes and exchange them for access tokens.
    confidence_band: high
cves:
  - id: CVE-2026-93354
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93354
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Taskview Community to version 1.56.0 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-93354 remediation
  mitigation_plan:
    - priority: immediate
      action: Restrict or disable the OAuth 2.0 Dynamic Client Registration endpoint
      owner: IT Operations
      addresses: CVE-2026-93354
      evidence: Vulnerability in OAuth 2.0 Dynamic Client Registration endpoint
---

Taskview Community versions prior to 1.56.0 contain a critical vulnerability in the OAuth 2.0 Dynamic Client Registration endpoint that permits unauthenticated access. By default, this endpoint is active and lacks any form of identity verification, enabling any actor on the network to register an arbitrary OAuth client. An attacker can leverage this to register their own client application, receive valid credentials (client_id and client_secret), and initiate malicious OAuth flows. This vulnerability poses a significant risk to the integrity of user accounts within affected Taskview deployments, as it facilitates full unauthorized access to API data and account information. Defending against this requires immediate patching or, as a temporary measure, ensuring that the Dynamic Client Registration endpoint is explicitly disabled or restricted to trusted internal network ranges if the business logic allows.

## Impact

Successful exploitation allows unauthenticated attackers to hijack user sessions and gain full API access to sensitive victim account data. Organizations utilizing Taskview Community to manage OAuth workflows are at high risk of large-scale account takeover events and data exfiltration through the application's API layer.

## Recommendation

- Upgrade Taskview Community to version 1.56.0 or later immediately to address the missing authentication in the OAuth registration endpoint.
- Audit logs for the OAuth 2.0 Dynamic Client Registration endpoint to identify any unauthorized or unexpected client registration requests originating from outside authorized administrative subnets.
- Review all registered OAuth clients for unrecognized or suspicious entries that may have been created by unauthorized actors during the exposure period.
