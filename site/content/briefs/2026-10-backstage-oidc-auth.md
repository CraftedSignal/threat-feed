---
title: Improper Authentication Vulnerability in Backstage OIDC Provider
slug: 2026-10-backstage-oidc-auth
description: A vulnerability in the Backstage OIDC authentication module allows authenticated users to spoof identities when using email-based resolution with unverified email providers, leading to unauthorized access.
date: "2026-10-07T22:55:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:backstage:plugin-auth-backend-module-oidc-provider:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve-2026-106488
  - backstage
vendors:
  - Backstage
products:
  - plugin-auth-backend-module-oidc-provider (< 0.4.20)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: A vulnerability in the Backstage OIDC authentication backend allows authenticated users to spoof identities.
    confidence_band: high
cves:
  - id: CVE-2026-106488
    cvss: 8.1
references:
  - https://github.com/advisories/GHSA-826h-28h9-65hg
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DevOps
  immediate_actions:
    - action: Upgrade @backstage/plugin-auth-backend-module-oidc-provider to 0.4.20
      owner: DevOps
      due: 48h
      evidence: Patched in @backstage/plugin-auth-backend-module-oidc-provider version 0.4.20
  mitigation_plan:
    - priority: immediate
      action: Disable email-based sign-in resolution for the OIDC provider
      owner: IT Operations
      addresses: CVE-2026-106488
      evidence: 'Workaround: Disable email-based sign-in resolution for the OIDC provider, or require the identity provider to verify email addresses.'
---

Backstage's `@backstage/plugin-auth-backend-module-oidc-provider` is affected by an improper authentication vulnerability, tracked as CVE-2026-106488. The flaw exists in the email-based identity resolution process when configured with OIDC providers that do not enforce email verification. An attacker who is authenticated via a malicious or misconfigured OIDC provider can supply an unverified email address that matches an existing user in the Backstage catalog. The application incorrectly maps the attacker's session to the identity of the victim user, allowing for full impersonation of that user's identity and associated permissions within the Backstage environment. This vulnerability affects versions prior to 0.4.20. Defenders should note that this vulnerability does not represent a code injection or direct system compromise, but rather a logic flaw in how identity claims are validated during the OIDC handshake.

## Impact

Successful exploitation allows for unauthorized access to catalog entities and sensitive resources managed by Backstage by assuming the identity of another user. This can lead to privilege escalation if the spoofed user account holds administrative roles or high-level access to internal developer portal documentation, service metadata, or infrastructure configurations. No specific victim counts have been reported, but organizations utilizing email-based OIDC identity resolution are at risk if their provider allows unverified addresses.

## Recommendation

- Upgrade the `@backstage/plugin-auth-backend-module-oidc-provider` package to version 0.4.20 or later to include the patch for CVE-2026-106488.
- Review OIDC provider configurations and disable email-based identity resolution if email verification cannot be strictly enforced at the provider level.
- Monitor authentication logs for unexpected account mappings or user sessions originating from non-standard or untrusted OIDC provider issuers.
