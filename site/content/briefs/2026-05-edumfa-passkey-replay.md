---
title: eduMFA Passkey Replay Vulnerability
slug: 2026-05-edumfa-passkey-replay
description: eduMFA versions prior to 2.9.1 are vulnerable to replay attacks due to a missing expiration flag in userless Passkey/WebAuthn challenges, potentially leading to unauthorized access.
date: "2026-05-18T15:37:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - replay-attack
  - authentication
  - webauthn
vendors:
  - eduMFA
products:
  - eduMFA (< 2.9.1)
references:
  - https://github.com/advisories/GHSA-j5rm-v3vh-vx94
rules:
  - title: Detect eduMFA Passkey Replay Attempt
    description: Detects potential replay attacks against eduMFA by monitoring for multiple authentication attempts using the same challenge ID.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
  - title: Detect eduMFA Userless Login Attempt
    description: Detects attempts to use userless login in eduMFA, which may be vulnerable to replay attacks in versions before 2.9.1. Use this rule to monitor the usage of userless logins.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

eduMFA versions prior to 2.9.1 are susceptible to a replay attack vulnerability affecting userless Passkey/WebAuthn authentication. This flaw stems from the absence of an expiration flag within the challenge generated during the authentication process. Consequently, an attacker could potentially capture a valid, unexpired challenge and reuse it to bypass authentication, even after the legitimate user's session has ended or the challenge should have expired. This issue was addressed in eduMFA version 2.9.1 by implementing validity information for userless challenges. Defenders should prioritize upgrading vulnerable instances of eduMFA to version 2.9.1 or later to mitigate this risk.

## Attack Chain

1.  User initiates a userless Passkey/WebAuthn authentication request against an eduMFA instance running a version prior to 2.9.1.
2.  eduMFA generates a challenge without proper expiration or validity constraints.
3.  Attacker intercepts the challenge during transmission or retrieves it from a compromised system.
4.  The legitimate user completes the authentication, granting access to protected resources.
5.  Attacker replays the previously intercepted challenge to the eduMFA instance.
6.  Due to the missing expiration check, eduMFA incorrectly validates the replayed challenge as legitimate.
7.  Attacker gains unauthorized access to the protected resources, impersonating the original user.
8.  Attacker performs actions within the system using the compromised session, potentially escalating privileges or exfiltrating sensitive data.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass multi-factor authentication and gain unauthorized access to systems and data protected by eduMFA. This can lead to data breaches, financial losses, and reputational damage. The impact is significant as it undermines the security guarantees provided by multi-factor authentication, especially in environments relying on userless Passkey/WebAuthn authentication.

## Recommendation

*   Upgrade all eduMFA installations to version 2.9.1 or later to remediate the vulnerability as described in the overview.
*   Deploy the Sigma rule "Detect eduMFA Passkey Replay Attempt" to identify potential replay attacks by monitoring for multiple authentication attempts using the same challenge.
*   If immediate patching is not possible, consider temporarily disabling userless login as suggested in the advisory.
