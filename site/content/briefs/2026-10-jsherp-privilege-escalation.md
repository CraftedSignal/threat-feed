---
title: Authorization Bypass in jshERP UserController
slug: 2026-10-jsherp-privilege-escalation
description: jshERP versions through 3.6 contain a missing authorization vulnerability in the UserController updateUser handler, allowing authenticated users to escalate privileges or modify other users' roles.
date: "2026-10-12T13:43:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jsherp:jsherp:*:*:*:*:*:*:*:*
vendors:
  - jshERP
products:
  - jshERP (<= 3.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Low-privilege attackers can send their own user id with the tenant administrator roleId to escalate privileges or rebind other tenant users' roles.
    confidence_band: high
cves:
  - id: CVE-2026-109185
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109185
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit user role modification logs for unauthorized privilege elevation.
      owner: SOC
      due: 48h
      evidence: Source document identifies insecure updateUser handler as the entry point.
  mitigation_plan:
    - priority: immediate
      action: Upgrade jshERP to a patched version beyond 3.6.
      owner: IT Operations
      addresses: CVE-2026-109185
      evidence: Source identifies vulnerability in versions <= 3.6.
---

jshERP versions up to and including 3.6 are vulnerable to a missing authorization flaw located within the UserController updateUser handler. This vulnerability enables an authenticated user to perform unauthorized privilege escalation by manipulating role assignments via the application API. Specifically, an attacker can submit a request containing their own user identifier paired with the role ID corresponding to a tenant administrator. Furthermore, the flaw permits the rebinding of roles for other users within the same tenant. Because this vulnerability facilitates horizontal and vertical privilege escalation, it represents a significant security risk for multi-tenant environments where role-based access control is the primary mechanism for security boundary enforcement. Defenders should investigate audit logs related to user role updates to identify potential abuse of this endpoint.

## Impact

Successful exploitation allows a low-privilege attacker to gain tenant administrator access, leading to full control over the affected tenant's data and configuration within the jshERP platform. In multi-tenant deployments, this compromise can lead to data exfiltration or unauthorized management of other users' accounts, undermining the integrity of the entire application deployment.

## Recommendation

- Identify all instances of jshERP version 3.6 or earlier in the environment.
- Monitor web application logs for POST or PUT requests directed at the UserController updateUser endpoint that indicate privilege changes for user IDs.
- Implement strict server-side authorization checks on all calls to the updateUser handler to ensure the requesting user has the appropriate administrative permissions before modifying roles.
