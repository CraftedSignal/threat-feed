---
title: OpenClaw Synology Chat Reply Delivery Vulnerability
slug: 2024-01-02-openclaw-synology-chat-vuln
description: A vulnerability exists in OpenClaw versions prior to 2026.3.22 where Synology Chat reply delivery can be rebound to a mutable username match instead of the stable numeric user_id, potentially leading to information disclosure or privilege escalation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - synology-chat
  - openclaw
  - vulnerability
vendors:
  - OpenClaw
  - Synology
products:
  - OpenClaw
  - Synology Chat
references:
  - https://github.com/advisories/GHSA-wv46-v6xc-2qhf
rules:
  - title: Detect OpenClaw Synology Chat Username Rebinding Attempt
    description: Detects potential attempts to exploit the OpenClaw Synology Chat username rebinding vulnerability by monitoring for suspicious configuration changes related to username resolution.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect OpenClaw Synology Chat Webhook Handler Modification
    description: Detects modification of webhook-handler.ts file, which could indicate attempts to revert the fix.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw is an open-source project that integrates with Synology Chat. A vulnerability was discovered where reply delivery could be misdirected. Specifically, versions of the `openclaw` npm package prior to 2026.3.22 are affected. This vulnerability allows for the potential rebinding of Synology Chat reply delivery from the intended user_id to a different user based on mutable username matches. This could lead to an attacker receiving sensitive information intended for another user, or potentially escalating privileges if the attacker can impersonate an administrator or other privileged user. The vulnerability was patched in version 2026.3.22, which keeps replies bound to the stable webhook user identifier unless an explicit dangerous opt-in is enabled.

## Attack Chain

1.  Attacker identifies a target user within the Synology Chat environment.
2.  Attacker creates a new Synology Chat user account with a username that closely resembles the target user's username or matches it if the target user has changed their username previously.
3.  The target user triggers a webhook event that generates a message in Synology Chat.
4.  The attacker's crafted account with a similar username causes OpenClaw to incorrectly resolve the reply delivery to the attacker's account due to the vulnerable username-based resolution logic in versions prior to 2026.3.22.
5.  Any replies intended for the original user_id are now routed to the attacker's account.
6.  The attacker intercepts and views potentially sensitive information contained within the misdirected replies.
7.  If the target user has elevated privileges, the attacker could potentially gain access to sensitive system configurations or other restricted resources by intercepting administrative communications.

## Impact

Successful exploitation of this vulnerability could lead to information disclosure, where an attacker gains access to private conversations and data intended for other users. In scenarios involving privileged users, the impact could escalate to privilege escalation, potentially compromising the entire Synology Chat environment. The number of affected users and organizations depends on the adoption rate of OpenClaw with Synology Chat.

## Recommendation

*   Upgrade the `openclaw` npm package to version 2026.3.22 or later to remediate the vulnerability.
*   Audit the `extensions/synology-chat/src/config-schema.ts` configuration to ensure the dangerous opt-in seam for username rebinding is disabled.
*   Deploy the Sigma rule provided below to monitor for potential exploitation attempts involving Synology Chat username manipulation.
