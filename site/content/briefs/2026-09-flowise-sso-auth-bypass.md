---
title: Authentication Bypass in Flowise SSO Callback
slug: 2026-09-flowise-sso-auth-bypass
description: Flowise versions up to 3.1.4 contain an authentication bypass vulnerability in the SSO callback logic that allows attackers to hijack pending user invitations and gain unauthorized organization access.
date: "2026-09-26T15:01:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:flowiseai:flowise:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - sso
  - flowise
vendors:
  - n8n GmbH
products:
  - Flowise (<= 3.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Flowise through 3.1.4 (Enterprise/platform mode with SSO enabled) contains an authentication bypass in the SSO login path.
    confidence_band: high
cves:
  - id: CVE-2026-100606
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100606
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review organizational access logs for suspicious SSO callbacks involving INVITED user accounts
      owner: SOC
      due: 24h
      evidence: The registration handler's token lookup and email match allow account status to flip to ACTIVE.
  mitigation_plan:
    - priority: immediate
      action: Disable SSO integration for Flowise platform/enterprise mode if not strictly required.
      owner: IT Operations
      addresses: CVE-2026-100606
      evidence: The bypass affects the SSO login path when SSO is enabled.
---

Flowise versions up to 3.1.4 are vulnerable to an authentication bypass when deployed in enterprise or platform mode with SSO enabled. The issue stems from the `verifyAndLogin` function in `SSOBase.ts`, which handles SSO callback requests for users with a status of `INVITED`. During this process, the application incorrectly copies the server-stored, single-use `tempToken` into the data payload sent to `AccountService.register()`. Because the registration handler validates the token against this server-side copy rather than a caller-supplied value, an attacker can bypass the invitation token requirement. By authenticating via a configured SSO provider using the email address of a pending invitee, an attacker can flip the user account status to `ACTIVE` and gain full access to the target organization's resources. This bypass is possible as long as the invitation remains valid, typically within a 24-hour window. No patches were available at the time of initial disclosure.

## Impact

Successful exploitation allows unauthenticated attackers to hijack user invitations, leading to unauthorized access to Flowise organizations. This enables attackers to impersonate invited users, access proprietary data, and manipulate application workflows within the organization, posing a significant risk to the confidentiality and integrity of platform environments.

## Recommendation

Prioritize the identification and monitoring of SSO authentication traffic for the Flowise application. Until a patch is released, disable SSO integration for Flowise enterprise or platform deployments if possible, or enforce strict access control lists on the SSO provider to restrict the scope of trusted users.
