---
title: Unauthenticated Account Takeover in FriendsOfFlarum OAuth via Discord Provider
slug: 2026-09-fof-oauth-takeover
description: An unauthenticated account takeover vulnerability exists in the fof/oauth extension due to improper validation of unverified email addresses returned by the Discord OAuth provider, allowing attackers to hijack existing Flarum accounts.
date: "2026-09-25T20:06:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:friendsofflarum:fof_oauth:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - cve-2026-92161
vendors:
  - FriendsOfFlarum
products:
  - fof/oauth (1.x < 1.7.4, 2.0.0-beta.x < 2.0.0-beta.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated account takeover vulnerability exists in fof/oauth when the Discord OAuth provider is enabled.
    confidence_band: high
cves:
  - id: CVE-2026-92161
    cvss: 9.8
references:
  - https://github.com/advisories/GHSA-g7vj-c29h-3h5m
  - https://github.com/FriendsOfFlarum/oauth/releases/tag/1.7.4
  - https://github.com/FriendsOfFlarum/oauth/releases/tag/2.0.0-beta.4
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade fof/oauth to 1.7.4 or 2.0.0-beta.4
      owner: IT Operations
      due: 24h
      evidence: Source Patched Versions section
  mitigation_plan:
    - priority: immediate
      action: Disable Discord OAuth provider in Flarum extension settings
      owner: IT Operations
      addresses: CVE-2026-92161
      evidence: Source Workarounds section
---

The FriendsOfFlarum `fof/oauth` extension (CVE-2026-92161) contains a critical vulnerability that allows unauthenticated account takeover. When the Discord OAuth provider is enabled, the extension fails to verify the `verified` flag returned by the Discord API. Discord may return an email address as unverified if the account's associated phone number has been validated, even if the email itself has not been confirmed. 

The `fof/oauth` extension incorrectly treats these unverified emails as trusted, passing them to the Flarum core `provideTrustedEmail()` function. If the provided email address matches an existing user on the forum, Flarum automatically links the attacker-controlled Discord identity to that account and logs the attacker in as the victim. This enables complete account takeover, including administrative accounts, provided the attacker knows the victim's email address. The vulnerability affects version series 1.x before 1.7.4 and 2.0.0-beta versions before 2.0.0-beta.4.

## Attack Chain

1. Attacker identifies a target Flarum forum that has the Discord OAuth provider enabled.
2. Attacker obtains the target victim's email address, which is associated with a Flarum account.
3. Attacker creates or configures a Discord account using the victim's email address as the primary account email.
4. Attacker verifies a phone number on the Discord account, which allows the email address to remain in an unverified state within the Discord ecosystem.
5. Attacker initiates an OAuth authentication flow via the targeted Flarum forum using the compromised Discord account.
6. The `fof/oauth` extension receives the OAuth callback from Discord, including the victim's email address marked with `"verified": false`.
7. The extension fails to validate the `"verified": false` flag and calls `provideTrustedEmail()` with the target's email.
8. Flarum core identifies the victim's account via the email address and completes the authentication, granting the attacker full access to the victim's session.

## Impact

The vulnerability allows for complete account takeover, including administrative accounts, without requiring user interaction or knowledge of the user's password. Any forum utilizing the `fof/oauth` extension with the Discord provider enabled is susceptible. The extent of the damage is dependent on the level of privilege held by the targeted accounts on the affected forums.

## Recommendation

1. Upgrade the `fof/oauth` extension to version 1.7.4 or 2.0.0-beta.4 or later immediately.
2. If an immediate upgrade is not feasible, disable the Discord OAuth provider in the Flarum extension settings to mitigate the risk of exploitation.
3. Audit user sessions and account linking logs for signs of suspicious OAuth association activity.
