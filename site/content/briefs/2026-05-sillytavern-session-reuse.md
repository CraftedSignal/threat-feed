---
title: SillyTavern Session Reuse After Password Change
slug: 2026-05-sillytavern-session-reuse
description: SillyTavern versions 1.17.0 and earlier do not invalidate existing sessions after a password change, allowing attackers with stolen session cookies to retain access, even after the victim resets their password, and nullifies the password reset as a recovery measure against session theft.
date: "2026-05-12T22:25:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - session-reuse
  - web-application
vendors:
  - npm
products:
  - sillytavern (<= 1.17.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
references:
  - https://github.com/advisories/GHSA-wmm3-h9qj-p5v6
rules:
  - title: Detect SillyTavern Session Cookie Use After Password Change
    description: Detects continued use of a SillyTavern session cookie after a password change event by monitoring API access following a password change.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
  - title: Detect SillyTavern API Access
    description: Detects access to SillyTavern API endpoints which can be used to detect post exploitation activity
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
rules_count: 2
---

SillyTavern, a popular open-source AI chatbot interface, is vulnerable to session reuse. Prior to version 1.18.0, changing a user's password does not invalidate existing session cookies. This vulnerability stems from the application's reliance on cookie-session for authentication, where session data is stored client-side. An attacker who has obtained a valid session cookie can maintain persistent access to a user's account, even after the user changes their password. The default cookie lifespan of 400 days gives attackers a very long window for potential exploitation. Defenders should ensure that their SillyTavern installations are upgraded to version 1.18.0 or later to mitigate this risk.

## Attack Chain

1. An attacker gains unauthorized access to a user's valid session cookie through methods like XSS, man-in-the-middle attacks, or physical access to the user's device.
2. The attacker imports the stolen cookie into their browser.
3. The attacker authenticates to the SillyTavern application using the imported cookie.
4. The victim, suspecting account compromise, changes their password via the `/api/users/change-password` endpoint or `/api/users/recover-step2` after initiating an account recovery.
5. The SillyTavern application updates the password hash in the database but does not invalidate the existing session cookie.
6. The attacker, still possessing the valid cookie, continues to access the victim's account and perform privileged actions.
7. The attacker views sensitive information, modifies user settings, or interacts with the AI chatbot as the compromised user.
8. The attacker maintains unauthorized access until the cookie expires, by default after 400 days.

## Impact

Successful exploitation allows attackers who have stolen session cookies to maintain persistent control over user accounts. Even after a password reset, attackers can continue accessing sensitive information, impersonate the user, and perform unauthorized actions. With a default cookie lifespan of 400 days, this vulnerability presents a significant risk of long-term account compromise, especially in environments where users may be slow to update their passwords or revoke sessions.

## Recommendation

*   Upgrade SillyTavern installations to version 1.18.0 or later to address the session invalidation vulnerability.
*   Enable web server logging and deploy the "Detect SillyTavern Session Cookie Use After Password Change" Sigma rule to identify suspicious activity associated with session reuse.
*   Implement strict cookie security policies, including setting the `HttpOnly` and `Secure` flags, to reduce the risk of session cookie theft.
