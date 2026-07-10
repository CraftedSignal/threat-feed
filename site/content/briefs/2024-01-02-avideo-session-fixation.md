---
title: AVideo Session Fixation Vulnerability (CVE-2026-33492)
slug: 2024-01-02-avideo-session-fixation
description: AVideo versions 26.0 and earlier are vulnerable to session fixation due to accepting arbitrary session IDs via the `PHPSESSID` GET parameter and disabled session regeneration, allowing attackers to hijack authenticated sessions.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-33492
  - avideo
  - session-fixation
  - web-application
vendors:
  - AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Account
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33492
rules:
  - title: Detect AVideo Session Fixation Attempt via PHPSESSID GET Parameter
    description: Detects potential session fixation attacks against AVideo by monitoring for HTTP requests with the PHPSESSID parameter in the GET request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1550.004
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Login without Session Regeneration
    description: Detects a login event on AVideo without subsequent session regeneration, indicating potential exploitation of CVE-2026-33492.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1550.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AVideo, an open-source video platform, is vulnerable to a session fixation attack (CVE-2026-33492) in versions up to and including 26.0. The vulnerability stems from the `_session_start()` function, which improperly accepts arbitrary session IDs via the `PHPSESSID` GET parameter. Furthermore, session regeneration is bypassed for specific blacklisted endpoints when the request originates from the same domain. Critically, the `User::login()` function explicitly disables session regeneration. This combination allows an attacker to set a victim's session ID before they authenticate, and subsequently hijack their authenticated session. This is a critical vulnerability as it can lead to complete account takeover. A patch is available in commit 5647a94d79bf69a972a86653fe02144079948785.

## Attack Chain

1.  Attacker identifies a vulnerable AVideo instance (version 26.0 or earlier).
2.  Attacker crafts a malicious link or uses another method to send the victim a URL to the AVideo site that includes a `PHPSESSID` parameter with a session ID controlled by the attacker (e.g., `https://example.com/?PHPSESSID=attacker_session_id`).
3.  The victim clicks the link and their browser sets the `PHPSESSID` cookie to the attacker-controlled value. The AVideo server starts a PHP session using the provided session ID.
4.  The victim logs into the AVideo platform. The `User::login()` function, due to the vulnerability, does not regenerate the session ID upon successful authentication.
5.  The victim's authenticated session continues to use the attacker-controlled `PHPSESSID`.
6.  The attacker uses the same `PHPSESSID` value in their own browser to access the AVideo site.
7.  The AVideo server authenticates the attacker as the victim because the session ID matches the victim's authenticated session.
8.  The attacker now has complete access to the victim's account, including their videos, personal information, and administrative privileges if applicable.

## Impact

Successful exploitation of this vulnerability allows an attacker to completely take over a user's account on the AVideo platform. This could lead to unauthorized access to sensitive video content, modification or deletion of videos, defacement of the platform, or further attacks leveraging the compromised account. The number of potential victims depends on the number of vulnerable AVideo instances and their user base, but the impact is significant for each compromised account.

## Recommendation

*   Apply the patch available in commit 5647a94d79bf69a972a86653fe02144079948785 to remediate the session fixation vulnerability.
*   Deploy the Sigma rule `Detect AVideo Session Fixation Attempt via PHPSESSID GET Parameter` to identify potential exploitation attempts (Sigma rule).
*   Monitor web server logs for requests containing the `PHPSESSID` parameter in the query string to identify potential session fixation attempts (webserver logs).
*   Consider implementing a web application firewall (WAF) rule to block requests containing the `PHPSESSID` parameter in the query string (webserver logs).
