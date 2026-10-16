---
title: Authentication Bypass in Webreaper Damselfly
slug: 2026-10-damselfly-auth-bypass
description: Webreaper Damselfly versions 4.5.3 and earlier contain an authentication bypass vulnerability in API routes that allows unauthenticated attackers to escalate privileges and perform administrative actions.
date: "2026-10-16T18:44:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:webreaper:damselfly:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - api-vulnerability
  - vulnerability-management
vendors:
  - Webreaper
products:
  - Damselfly (<= 4.5.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Webreaper Damselfly through 4.5.3 contains an authentication bypass vulnerability that allows unauthenticated attackers to access all /api/* routes.
    confidence_band: high
cves:
  - id: CVE-2026-111626
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111626
rules:
  - title: Detect CVE-2026-111626 Exploitation - Unauthorized API User Modification
    description: Detects potential exploitation of CVE-2026-111626 by identifying unauthorized PUT or POST requests to the /api/users endpoint which indicate attempts to create admin accounts or reset passwords.
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
    - IT Operations
  immediate_actions:
    - action: Upgrade Webreaper Damselfly to the version providing the fix for CVE-2026-111626.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111626 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade to a patched version beyond 4.5.3.
      owner: IT Operations
      addresses: CVE-2026-111626
      evidence: Source documentation for Damselfly vulnerabilities
---

Webreaper Damselfly versions 4.5.3 and earlier contain a critical authentication bypass vulnerability (CVE-2026-111626) affecting the API layer. The flaw stems from commented-out authorization attributes on all /api/* routes, which effectively disables access control checks for these endpoints. This allows remote, unauthenticated attackers to interact with sensitive API functions intended for administrative use. 

By leveraging this oversight, attackers can manipulate the user management API to create new administrator accounts or modify existing credentials. The vulnerability allows for the full takeover of the application instance, as an attacker can register themselves as an administrator or reset the passwords of existing authorized users to gain persistence and full control over the application environment.

## Impact

Successful exploitation results in full unauthorized administrative access to the affected Webreaper Damselfly instance. Attackers can create rogue accounts, modify existing user passwords, and access sensitive data stored within the application. This vulnerability poses a severe risk to any organization using Damselfly as it allows for trivial system takeover without prior authentication.

## Recommendation

- Upgrade Webreaper Damselfly to a patched version beyond 4.5.3 immediately.
- Review application access logs for unexpected requests to the /api/users endpoint, specifically looking for PUT or POST requests originating from non-authorized source IPs.
- Audit the user management logs for the creation of new accounts or unauthorized password reset events that do not correlate with legitimate user activity.
