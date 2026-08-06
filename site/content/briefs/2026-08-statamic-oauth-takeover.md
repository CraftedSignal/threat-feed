---
title: Statamic CMS Account Takeover via Unverified OAuth Email Matching
slug: 2026-08-statamic-oauth-takeover
description: An unauthenticated attacker can achieve account takeover by leveraging unverified OAuth email matching in Statamic CMS, allowing unauthorized authentication as existing users including administrators.
date: "2026-08-06T21:29:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - oauth
  - account-takeover
  - cms
  - authentication-bypass
vendors:
  - Statamic
products:
  - Statamic CMS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: An unauthenticated attacker could sign in as an existing user, potentially including a super admin, without their password.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-93qh-5269-9wcf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64665
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Statamic CMS to version 5.74.1 or 6.24.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-64665 fix availability
    - action: Review and restrict active OAuth providers
      owner: Security Engineering
      due: 24h
      evidence: Source workaround
---

Statamic CMS versions prior to 5.74.1 and versions in the 6.0.0 through 6.23.x series are vulnerable to an account takeover flaw, tracked as CVE-2026-64665. The vulnerability resides in the OAuth authentication flow, where the application improperly associates incoming OAuth responses with local user accounts based solely on email addresses, without verifying that the email address is marked as verified by the identity provider. 

If an administrator has enabled an OAuth provider that does not mandate email verification, an attacker can register an account at the identity provider using an email address belonging to an existing Statamic user. Upon successful OAuth authentication, the Statamic application incorrectly maps the attacker's session to the existing target account, granting the attacker full access to that user's privileges, including super-administrator rights. This bypasses standard password-based authentication and two-factor authentication, significantly increasing the risk of full site compromise.

## Impact

The vulnerability allows unauthenticated attackers to hijack accounts, including highly privileged administrator accounts. Successful exploitation leads to full site administration, potentially enabling data exfiltration, backdooring the application, or modifying site content. The scope affects all Statamic deployments where OAuth is enabled with non-strictly configured third-party providers.

## Recommendation

- Upgrade Statamic CMS to version 5.74.1 or 6.24.0 immediately to apply the fix for CVE-2026-64665.
- Review OAuth provider configurations in the Statamic control panel and ensure that only identity providers providing verified email attributes are in use.
- If current identity providers do not guarantee email verification, disable OAuth authentication until providers with secure configurations can be implemented.
