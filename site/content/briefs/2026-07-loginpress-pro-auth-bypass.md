---
title: CVE-2026-12597 - LoginPress Pro WordPress Plugin Authentication Bypass
slug: 2026-07-loginpress-pro-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-12597) in the LoginPress Pro WordPress plugin versions up to and including 6.2.3 allows unauthenticated attackers to gain initial access to any existing WordPress user account, including administrators, by exploiting a flaw in its GitHub OAuth callback that fails to verify the status of email addresses returned by GitHub's /user/emails endpoint.
date: "2026-07-10T00:19:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - authentication-bypass
  - plugin-vulnerability
  - cve
vendors:
  - WPBrigade
products:
  - LoginPress Pro (<= 6.2.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: unauthenticated attackers to log in as any existing WordPress user, including administrators
    confidence_band: high
cves:
  - id: CVE-2026-12597
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12597
---

A critical authentication bypass vulnerability, identified as CVE-2026-12597, has been discovered in the LoginPress Pro plugin for WordPress, affecting all versions up to and including 6.2.3. The flaw resides within the `loginpress_on_github_login()` function, which is responsible for handling GitHub OAuth callbacks. This function erroneously trusts the first email address returned by GitHub's `/user/emails` endpoint (`profile[0]['email']`) as a binding identifier without verifying if the email holds a `verified === true` status. This oversight enables unauthenticated attackers to log in as any existing WordPress user, including those with administrative privileges. Attackers can achieve this by adding an unverified email address to their GitHub profile that matches a target WordPress account, then triggering the OAuth callback. The plugin will subsequently call `get_user_by('email', ...)` and establish an authenticated session for the matched account, bypassing proper authentication checks.

## Attack Chain

1. Attacker identifies a WordPress website utilizing the vulnerable LoginPress Pro plugin.
2. Attacker creates a new GitHub account or uses an existing one.
3. Attacker adds an unverified email address to their GitHub profile that precisely matches the email of an existing target WordPress user (e.g., an administrator).
4. Attacker crafts and sends an HTTP request to the vulnerable WordPress site's GitHub OAuth callback endpoint, including a standard `code` parameter obtained through the OAuth flow.
5. The LoginPress Pro plugin's `loginpress_on_github_login()` function processes the callback.
6. The plugin queries GitHub's `/user/emails` API endpoint to retrieve the user's associated email addresses.
7. If the attacker-controlled unverified email is returned first in GitHub's response array (`profile[0]['email']`), the plugin blindly accepts it.
8. The plugin then calls `get_user_by('email', ...)` using this unverified email and establishes an authenticated session for the matched WordPress user.
9. Attacker successfully gains unauthorized access to the target WordPress user account, potentially leading to full site compromise if the account is an administrator.

## Impact

The successful exploitation of CVE-2026-12597 grants unauthenticated attackers immediate access to any user account on a vulnerable WordPress site, including administrative accounts. This direct authentication bypass can lead to complete compromise of the WordPress instance, allowing attackers to inject malicious code, deface the website, exfiltrate sensitive data, or establish persistent backdoors. The vulnerability has a CVSS v3.1 Base Score of 8.1, reflecting its high severity and potential for widespread damage. The compromise of administrator accounts is particularly devastating, enabling full control over the website's content, users, and settings.

## Recommendation

* Immediately update the LoginPress Pro plugin to a version greater than 6.2.3 to patch CVE-2026-12597.
* Review web server access logs for unusual or repeated attempts to access the GitHub OAuth callback endpoint `/wp-login.php?loginpress_github_oauth=1` or similar, especially those resulting in successful logins from unknown IPs.
