---
title: OpenCart Session Fixation Vulnerability (CVE-2021-47923)
slug: 2026-05-opencart-session-fixation
description: OpenCart 3.0.3.8 is vulnerable to session fixation (CVE-2021-47923), allowing attackers to hijack user sessions by injecting arbitrary values into the OCSESSID cookie, leading to unauthorized access.
date: "2026-05-10T13:18:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - opencart
  - session-fixation
  - CVE-2021-47923
  - webserver
vendors:
  - OpenCart
products:
  - OpenCart 3.0.3.8
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
cves:
  - id: CVE-2021-47923
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47923
rules:
  - title: Detect OpenCart Session Fixation Attempt via OCSESSID Manipulation
    description: Detects CVE-2021-47923 exploitation - An attempt to manipulate the OCSESSID cookie, indicating a session fixation attack against OpenCart.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect OpenCart Session Fixation - High Sc-Status
    description: Detects CVE-2021-47923 exploitation - HTTP request with a suspicious OCSESSID and a high sc-status (4xx, 5xx).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

OpenCart 3.0.3.8 is susceptible to a session fixation vulnerability, identified as CVE-2021-47923. This flaw allows a remote attacker to hijack legitimate user sessions by injecting arbitrary values into the `OCSESSID` cookie. By setting a malicious `OCSESSID` value, the attacker can force the server to associate the victim's session with the attacker-controlled session ID. This vulnerability enables unauthorized access to user accounts without requiring the attacker to know the user's credentials directly. A successful attack could lead to account takeover, data theft, and modification of user profiles.

## Attack Chain

1.  The attacker identifies an OpenCart 3.0.3.8 instance.
2.  The attacker crafts a malicious `OCSESSID` cookie value.
3.  The attacker injects the malicious `OCSESSID` cookie value into a victim's browser session. This can be achieved through various methods, such as phishing or man-in-the-middle attacks.
4.  The victim visits the OpenCart site, and their browser sends the manipulated `OCSESSID` cookie.
5.  The OpenCart server accepts the attacker-controlled `OCSESSID` value and associates it with the victim's session.
6.  The attacker uses the same malicious `OCSESSID` cookie to access the OpenCart site.
7.  The server recognizes the attacker's session as the victim's, granting the attacker unauthorized access.
8.  The attacker can now perform actions as the victim, such as viewing personal information, modifying settings, or making purchases.

## Impact

Successful exploitation of this session fixation vulnerability can result in complete account takeover. An attacker can gain unauthorized access to sensitive user data, including personal information, order history, and payment details. This can lead to financial loss for the victim, reputational damage to the OpenCart store, and potential legal liabilities. Given the high CVSS score (9.8), this vulnerability poses a significant risk to OpenCart users.

## Recommendation

*   Upgrade to a patched version of OpenCart that addresses CVE-2021-47923.
*   Deploy the Sigma rule `Detect OpenCart Session Fixation Attempt via OCSESSID Manipulation` to monitor for suspicious OCSESSID cookie values.
*   Implement server-side checks to validate the legitimacy of the `OCSESSID` cookie.
*   Enforce strict cookie policies, including setting the `HttpOnly` and `Secure` flags for the `OCSESSID` cookie to prevent client-side script access and transmission over unencrypted connections.
