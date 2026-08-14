---
title: Authorizer Zero-Click Account Takeover via OAuth Identity Linking
slug: 2026-08-authorizer-oauth-takeover
description: Authorizer suffers from a zero-click account takeover vulnerability (CVE-2026-35511) where attackers can link OAuth identities to unverified accounts, gaining persistent password access to victim accounts.
date: "2026-08-14T20:07:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - account-takeover
  - oauth
  - authentication-bypass
  - cve-2026-35511
vendors:
  - Authorizer
products:
  - authorizer
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1136.001
    technique_name: 'Create Account: Local Account'
    evidence: Attacker signs up with victim@company.com using email/password. Attacker sets a known password but does NOT click the email verification link.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.001
    technique_name: 'Create Account: Local Account'
    evidence: The attacker maintains persistent password-based access to the victim's account even if the victim later revokes Authorizer's OAuth access.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-29rf-f4vv-pvq6
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Authorizer to version 0.0.0-20260807033110-66fe488fd2a4
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends update to patch logic flaw
  hunt_leads:
    - lead: Search for unverified accounts that suddenly transitioned to verified via OAuth providers
      technique_id: T1136.001
      data_needed:
        - Database logs or application audit trails
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows automated verification of unverified accounts upon OAuth link
  mitigation_plan:
    - priority: immediate
      action: Disable OAuth login for non-verified accounts
      owner: Security Engineering
      addresses: CVE-2026-35511
      evidence: Suggested fix in source advisory
---

Authorizer, an open-source authentication platform, contains a critical identity linking vulnerability (CVE-2026-35511) that allows for zero-click account takeover. The flaw exists in the OAuth callback handler, which incorrectly merges identity provider data into existing unverified accounts without validating the ownership of the associated email address. An attacker can pre-register an account using a target's email address and a custom password without verifying the email. When the victim subsequently performs a legitimate OAuth login, the application links the OAuth identity to the attacker's pre-staged account, marks the email as verified, and retains the attacker's password. This grants the attacker persistent, unauthorized access to the victim's account, including all data added after the OAuth login. This vulnerability affects all Authorizer deployments using versions prior to 0.0.0-20260807033110-66fe488fd2a4.

## Attack Chain

1. The attacker registers a new account on an Authorizer instance using the target's email address (`victim@company.com`) and a password known only to the attacker.
2. The attacker intentionally ignores the email verification prompt, leaving the account in the database with `EmailVerifiedAt = nil`.
3. The victim, unaware of the pre-staged account, logs in to the platform using a legitimate third-party OAuth provider (e.g., Google or GitHub).
4. The OAuth callback handler processes the request and identifies that an account with `victim@company.com` already exists in the local database.
5. The application merges the OAuth identity into the attacker's account, updating the `SignupMethods` field to include the provider.
6. The application logic automatically verifies the account's email address (`EmailVerifiedAt` is set to the current timestamp), trusting the OAuth identity without validating ownership.
7. The application saves the merged user state to the database, leaving the attacker's initial password intact and valid.
8. The attacker authenticates to the account using the email and their original password, successfully performing an account takeover.

## Impact

Successful exploitation allows an attacker to achieve full account takeover. The attacker maintains persistent password-based access to the victim's account regardless of whether the victim later revokes the OAuth linkage. This leads to unauthorized data access and the potential for long-term credential abuse across all configured OAuth providers supported by Authorizer, including Google, GitHub, Facebook, and Microsoft.

## Recommendation

Prioritized actions for security and platform engineering teams:
- Update all Authorizer instances to version 0.0.0-20260807033110-66fe488fd2a4 or later immediately.
- Review database logs for accounts where `EmailVerifiedAt` was updated automatically via an OAuth callback flow to identify potentially compromised accounts.
- If immediate patching is not possible, disable OAuth identity linking and require re-authentication via the primary password method to ensure account ownership.
- Audit all user accounts for inconsistencies in `SignupMethods` or unexpected verification timestamps that coincide with OAuth login events.
