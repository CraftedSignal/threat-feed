---
title: WebPros cPanel & WHM and WP2 Authentication Bypass Vulnerability (CVE-2026-41940)
slug: 2024-01-cpanel-auth-bypass
description: CVE-2026-41940 is an authentication bypass vulnerability in WebPros cPanel & WHM and WP2 (WordPress Squared) that allows unauthenticated remote attackers to gain unauthorized access to the control panel.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cpanel
  - whm
  - wp2
  - wordpress
  - authentication-bypass
  - cve-2026-41940
  - initial-access
vendors:
  - WebPros
products:
  - cPanel & WHM
  - WP2 (WordPress Squared)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-41940
    cvss: 9.8
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-41940
  - https://support.cpanel.net/hc/en-us/articles/40073787579671-cPanel-WHM-Security-Update-04-28-2026
  - https://docs.cpanel.net/release-notes/release-notes/
  - https://docs.wpsquared.com/changelogs/versions/changelog/#13617
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41940
rules:
  - title: Detect cPanel/WHM Authentication Bypass Attempt
    description: Detects potential attempts to exploit the cPanel/WHM authentication bypass vulnerability (CVE-2026-41940) by monitoring for suspicious HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect cPanel Account Creation via Control Panel
    description: Detects potential malicious account creation via cPanel control panel after a potential authentication bypass. Adjust `Details` regex to match your cPanel logging.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1136
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WebPros cPanel & WHM (WebHost Manager) and WP2 (WordPress Squared) are affected by an authentication bypass vulnerability, identified as CVE-2026-41940. This flaw exists within the login flow, potentially granting unauthenticated remote attackers unauthorized access to the control panel. Successful exploitation allows attackers to bypass normal authentication mechanisms and directly access sensitive administrative functions within cPanel & WHM and WP2. Defenders should apply vendor-provided mitigations or discontinue use of the product if mitigations are not available. The vulnerability was disclosed in April 2026, and mitigations should be applied by May 3, 2026.

## Attack Chain

1.  The attacker identifies a vulnerable cPanel & WHM or WP2 instance.
2.  The attacker crafts a malicious HTTP request exploiting the authentication bypass vulnerability in the login flow.
3.  The request is sent to the target server, bypassing authentication checks.
4.  The server incorrectly processes the request, granting the attacker an authenticated session.
5.  The attacker leverages the authenticated session to access administrative interfaces and settings.
6.  The attacker modifies server configurations, potentially creating new administrative accounts.
7.  The attacker installs malicious plugins or software through the control panel.
8.  The attacker achieves full control over the web server and hosted websites.

## Impact

Successful exploitation of CVE-2026-41940 can lead to complete compromise of the affected cPanel & WHM or WP2 server. This can result in data breaches, website defacement, malware distribution, and denial-of-service attacks. The impact is significant due to the widespread use of cPanel & WHM in web hosting environments. Compromised servers could be leveraged for further attacks against other systems and networks.

## Recommendation

*   Apply mitigations provided by WebPros as detailed in their security update advisory to address CVE-2026-41940.
*   Deploy the Sigma rule "Detect cPanel/WHM Authentication Bypass Attempt" to identify potential exploitation attempts in web server logs.
*   If mitigations cannot be immediately applied, follow BOD 22-01 guidance for cloud services, potentially isolating the affected system until patched.
*   Consider discontinuing use of the affected product if patches or mitigations are unavailable, as advised in the original CISA KEV entry.
