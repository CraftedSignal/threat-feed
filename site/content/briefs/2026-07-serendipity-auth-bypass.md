---
title: Authentication Context Confusion in Serendipity
slug: 2026-07-serendipity-auth-bypass
description: Serendipity versions prior to 2.6.1 are vulnerable to an authentication context confusion flaw allowing an authenticated Editor to escalate privileges to Administrator via username collision.
date: "2026-07-30T15:31:27Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - s9y
products:
  - Serendipity
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An authenticated Editor can create a username collision with an Administrator account and obtain administrative privileges.
    confidence_band: high
cves:
  - id: CVE-2026-67351
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67351
  - https://github.com/s9y/Serendipity/security/advisories/GHSA-v645-243f-jwgh
  - https://www.vulncheck.com/advisories/serendipity-authentication-bypass-via-username-collision
---

Serendipity versions prior to 2.6.1 contain an authentication context confusion vulnerability (CVE-2026-67351) stemming from a flaw in how the application manages user sessions and password validation. The vulnerability occurs because the password validation routine and the session loading mechanism operate independently, failing to confirm that the user record utilized for session initialization matches the one successfully authenticated. 

An authenticated user with 'Editor' privileges can exploit this by creating a username collision that forces the application to load the session data of an Administrator account while validating credentials against the Editor's own password. This allows an attacker to bypass standard access controls and assume full administrative privileges. This vulnerability is rated with a CVSS v3.1 score of 8.8, posing a significant risk to the integrity and confidentiality of Serendipity deployments.

## Attack Chain

1. Attacker maintains an 'Editor' level account on the target Serendipity instance.
2. Attacker researches or identifies the username of a target Administrator account.
3. Attacker triggers a username collision condition within the Serendipity user database or authentication handling logic.
4. Attacker initiates an authentication request to the web application.
5. The application performs password validation using the attacker's Editor credentials.
6. The session management component fails to enforce a binding between the validated user and the resulting session data.
7. The application initializes the session using the Administrator's user record based on the collided username.
8. Attacker gains full administrative access to the platform.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to elevate their privileges to Administrator. This grants the attacker full control over the Serendipity installation, including the ability to modify site content, alter configurations, install malicious plugins, and potentially execute arbitrary code on the underlying server if administrative plugins are used maliciously.

## Recommendation

1. Upgrade all instances of Serendipity to version 2.6.1 or higher immediately to address the underlying authentication logic flaw.
2. Review application-level access logs for evidence of suspicious account transitions or unexpected privilege changes associated with 'Editor' accounts.
3. Audit the user management database for duplicate or conflicting usernames that could facilitate collision-based attacks.
