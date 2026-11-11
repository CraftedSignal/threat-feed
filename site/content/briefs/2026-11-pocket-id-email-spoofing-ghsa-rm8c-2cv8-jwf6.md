---
brief_id: brief-2026-11-11-pocket-id-email-spoofing-ghsa-rm8c-2cv8-jwf6
event_id: brief-2026-11-11-pocket-id-email-spoofing-ghsa-rm8c-2cv8-jwf6
revision: 1
activity_at: "2026-11-11T16:05:27Z"
title: 'Pocket ID: Arbitrary verified email spoofing (CVE-2026-115770)'
slug: 2026-11-pocket-id-email-spoofing-ghsa-rm8c-2cv8-jwf6
description: Pocket ID fails to cryptographically bind email verification tokens to target addresses, allowing authenticated users to spoof verified email claims for account takeover on relying applications.
date: "2026-11-11T16:05:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:pocket-id:pocket-id:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - identity-provider
  - oidc
  - cve-2026-115770
vendors:
  - Pocket ID
products:
  - pocket-id (< 0.0.0-20260727180059-43aaccd5bfac)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    subtechnique_id: T1550.001
    subtechnique_name: Application Access Token
    evidence: An authenticated Pocket ID user can request an email-verification token while their account uses an address they control, change the account email address, and then redeem the previously issued token.
    confidence_band: high
cves:
  - id: CVE-2026-115770
    cvss: 9.6
    epss: 0.00166
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-rm8c-2cv8-jwf6
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Identity Infrastructure Team
  immediate_actions:
    - action: Upgrade Pocket ID backend to version 0.0.0-20260727180059-43aaccd5bfac
      owner: Identity Infrastructure Team
      due: 24h
      evidence: Source advisory specifies version 0.0.0-20260727180059-43aaccd5bfac as the fix
  hunt_leads:
    - lead: Investigate logs for account updates followed by suspicious verification token redemption events.
      technique_id: T1550.001
      data_needed:
        - Application audit logs for /api/users/me/verify-email and /api/users/me
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The reproduction steps outline specific API calls that result in state transitions and email verification.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 0.0.0-20260727180059-43aaccd5bfac
      owner: Identity Infrastructure Team
      addresses: CVE-2026-115770
      evidence: Vendor advisory provides the specific patched version.
---

Pocket ID (CVE-2026-115770) contains an authentication integrity flaw where email verification tokens are bound only to the user ID rather than the email address being verified. This allows an authenticated user to initiate an email verification process for an address they control, subsequently update their account to a victim's address, and finally redeem the original, still-valid verification token to mark the victim's address as verified. 

## Attack Chain

1. Attacker authenticates to their own Pocket ID account using an attacker-controlled email address.
2. Attacker invokes the API to request an email verification token.
3. Attacker receives the verification token at the controlled email address.
4. Attacker updates their account profile via API, replacing their email address with the victim's target address.
5. Pocket ID updates the account email to the victim's address but retains the previously issued verification token.
6. Attacker redeems the original verification token against the account, causing Pocket ID to mark the victim's address as verified.
7. Attacker completes an OIDC flow with the relying party, which consumes the false 'email_verified: true' claim to link the attacker's identity to the victim's existing account.

## Impact

Successful exploitation results in arbitrary verified email spoofing within the Pocket ID OIDC provider. Relying applications that utilize the `email` and `email_verified` claims for account linking or auto-provisioning are vulnerable to cross-application account takeover, potentially exposing victim data and permissions.

## Recommendation

1. Immediately upgrade Pocket ID backend to version 0.0.0-20260727180059-43aaccd5bfac or later.
2. Invalidate all existing unredeemed email verification tokens upon any modification of the account email address.
3. Audit OIDC relying party configurations to ensure that account linking logic does not trust `email_verified` claims without additional multi-factor authentication or secondary identity verification.
4. Ensure all future verification tokens are cryptographically bound to the specific target email address, ensuring token redemption fails if the email address has changed.
