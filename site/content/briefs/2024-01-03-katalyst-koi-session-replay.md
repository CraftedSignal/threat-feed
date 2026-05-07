---
title: Katalyst Koi Session Cookies Replayable After Logout
slug: 2024-01-03-katalyst-koi-session-replay
description: Katalyst Koi versions before 4.20.0 and between 5.0.0 and 5.6.0 fail to invalidate admin session cookies upon logout, allowing attackers with a valid cookie to maintain unauthorized access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - session-replay
  - vulnerability
  - authentication
vendors:
  - RubyGems
  - Rails
products:
  - katalyst-koi (< 4.20.0)
  - katalyst-koi (>= 5.0.0, < 5.6.0)
  - Rails
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1553
    technique_name: Subvert Trust Relationships
references:
  - https://github.com/advisories/GHSA-4cx3-3c38-j9vv
  - https://guides.rubyonrails.org/v5.2.0/security.html#replay-attacks-for-cookiestore-sessions
rules:
  - title: Detect Katalyst Koi Session Replay Attempt
    description: Detects attempts to use a session cookie after a user has logged out, indicating a potential session replay attack against Katalyst Koi.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1553.002
    data_sources:
      - webserver
      - linux
  - title: Detect Katalyst Koi Admin Access Without Recent Login
    description: Detects access to admin functionality without a corresponding recent login event, potentially indicating a session replay attack.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1553.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Katalyst Koi is vulnerable to a session replay attack where admin session cookies are not invalidated when an admin user logs out. This vulnerability allows an attacker who has previously obtained a valid admin session cookie to continue accessing admin functionalities even after the legitimate admin user has logged out. The unauthorized access persists until the cookie expires or the session secrets are rotated. This issue affects applications using Koi admin authentication, where admin session cookies may have been exposed through various means, such as caching, interception, or retention. Users should upgrade to the patched Koi releases (4.20.0 or 5.6.0) to mitigate this vulnerability. The vulnerability was published May 7, 2026.

## Attack Chain

1. An attacker gains unauthorized access to a valid admin session cookie, potentially through network sniffing, cross-site scripting (XSS), or stolen credentials.
2. A legitimate admin user authenticates to the Katalyst Koi application and receives a session cookie.
3. The attacker intercepts or otherwise obtains a copy of this valid admin session cookie.
4. The legitimate admin user logs out of the Katalyst Koi application.
5. The Katalyst Koi application fails to invalidate the existing admin session cookie upon logout.
6. The attacker replays the stolen admin session cookie in subsequent requests to the Katalyst Koi application.
7. The Katalyst Koi application incorrectly authenticates the attacker, granting them continued access to admin functionalities.
8. The attacker performs unauthorized actions within the application, such as modifying data, changing configurations, or accessing sensitive information until the cookie expires.

## Impact

Successful exploitation of this vulnerability allows an attacker to maintain persistent, unauthorized access to administrative functions within the Katalyst Koi application. The impact can include data breaches, unauthorized modifications to the application configuration, and potential compromise of sensitive user data. The vulnerability impacts all applications using Koi admin authentication where an admin session cookie may have been exposed, cached, intercepted, or otherwise retained after logout.

## Recommendation

*   Upgrade to Katalyst Koi version 4.20.0 or 5.6.0, or backport the fix to invalidate session cookies after logout, as recommended in the advisory.
*   Implement multi-factor authentication (MFA) to reduce the risk of session cookie theft.
*   Deploy the Sigma rule to detect unauthorized access using replayed session cookies.
*   Monitor web server logs for suspicious activity related to session management (e.g., unusual cookie usage) to identify potential exploitation attempts.
*   Review and update session management policies to ensure session cookies are properly invalidated upon logout.
