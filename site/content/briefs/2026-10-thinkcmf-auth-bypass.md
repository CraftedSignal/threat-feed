---
title: Incorrect Authorization Vulnerability in ThinkCMF RestAdminBaseController
slug: 2026-10-thinkcmf-auth-bypass
description: An incorrect authorization flaw in ThinkCMF RestAdminBaseController allows restricted administrators to bypass access controls, leading to privilege escalation and unauthorized data access.
date: "2026-10-15T22:50:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:thinkcmf:thinkcmf:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - web
vendors:
  - ThinkCMF
products:
  - ThinkCMF (<= 8.0.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker can exploit this to perform sensitive actions, such as escalating their own privileges to full administrator.
    confidence_band: high
cves:
  - id: CVE-2026-111352
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111352
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review and restrict access to administrative REST API endpoints.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111352 incorrect authorization in RestAdminBaseController
  mitigation_plan:
    - priority: immediate
      action: Upgrade ThinkCMF to a patched version beyond 8.0.1.
      owner: IT Operations
      addresses: CVE-2026-111352
      evidence: Source states vulnerability exists through 8.0.1
---

ThinkCMF versions through 8.0.1 are vulnerable to an incorrect authorization flaw located within the RestAdminBaseController. The vulnerability originates from the Auth::check() function, which fails to enforce access control when no explicit 'admin_api' rule is defined for a given endpoint. This failure results in an open state, granting access to restricted REST API endpoints to any user possessing a valid admin-type API token. 

An attacker with low-level administrative credentials can exploit this misconfiguration to interact with restricted API methods. This scope includes the ability to exfiltrate sensitive member data, such as email addresses and mobile numbers, the ability to disable user accounts, and the critical capability to invoke the PUT admin/roles/{id}/authorize endpoint to escalate their own account privileges to full administrator. This vulnerability poses a significant risk to the integrity and confidentiality of the ThinkCMF management environment.

## Attack Chain

1. Attacker gains access to a low-privilege administrative API token via credential compromise or insider access.
2. Attacker inspects application API endpoints to identify routes handled by RestAdminBaseController.
3. Attacker crafts a malicious HTTP PUT request directed at the /admin/roles/{id}/authorize endpoint.
4. The application triggers RestAdminBaseController which calls the flawed Auth::check() function.
5. Auth::check() fails to validate the request because no specific 'admin_api' rule is present, bypassing the permission check.
6. The application processes the request, granting the attacker's target account full administrative permissions.
7. Attacker logs in with the elevated account to perform full administrative management or data exfiltration.

## Impact

Successful exploitation of CVE-2026-111352 allows unauthorized users to perform sensitive administrative actions. This includes unauthorized access to user databases (emails, mobile numbers), disruption of service through account disabling, and full privilege escalation to the super-administrator level, which can result in a total compromise of the application and underlying data.

## Recommendation

* Monitor web server logs for high-frequency or unauthorized calls to /admin/roles/{id}/authorize or endpoints returning sensitive user metadata.
* Audit current administrative API permissions and ensure all custom endpoints have explicit 'admin_api' rules defined within the controller logic.
* Evaluate the necessity of all active admin-type API tokens and revoke those associated with compromised or inactive accounts.
