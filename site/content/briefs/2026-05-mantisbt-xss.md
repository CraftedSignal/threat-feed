---
title: MantisBT Vulnerable to XSS via Font Family Preference Update (CVE-2026-40596)
slug: 2026-05-mantisbt-xss
description: MantisBT versions 2.11.0 through 2.28.1 are vulnerable to cross-site scripting (XSS) via the user account font family preference, allowing an authenticated attacker to inject arbitrary HTML that is reflected on every page, potentially leading to account takeover when combined with a CSP bypass vulnerability.
date: "2026-05-11T19:35:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - account-takeover
  - cve-2026-40596
  - ghsa
vendors:
  - MantisBT
products:
  - mantisbt (>= 2.11.0, <= 2.28.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-j3v9-553h-x28j
  - https://github.com/mantisbt/mantisbt/security/advisories/GHSA-9c3j-xm6v-j7j3
  - CVE-2026-40596
rules:
  - title: Detect MantisBT XSS Attempt via User Profile Update
    description: Detects attempts to inject malicious code via the font family field in MantisBT user profile updates related to CVE-2026-40596.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1547.001
    data_sources:
      - webserver
  - title: Detect MantisBT Account Takeover Attempt via Cookie Manipulation
    description: Detects suspicious changes to user cookies after a potential XSS exploit in MantisBT, indicating a possible account takeover.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - impact
    techniques:
      - T1499.004
      - T1539
    data_sources:
      - webserver
rules_count: 2
---

MantisBT, a web-based bug tracking system, is susceptible to a cross-site scripting (XSS) vulnerability affecting versions 2.11.0 to 2.28.1. This flaw (CVE-2026-40596) allows any authenticated user to inject arbitrary HTML code by modifying their account's font family preference. The injected payload is then reflected on every page the user visits within the MantisBT application, posing a significant risk. A separate CSP bypass vulnerability ([GHSA-9c3j-xm6v-j7j3](https://github.com/mantisbt/mantisbt/security/advisories/GHSA-9c3j-xm6v-j7j3)) exists in MantisBT. Leveraging both vulnerabilities, an attacker could potentially achieve account takeover. This combination of vulnerabilities enables attackers to execute malicious scripts in the context of other users, leading to sensitive data theft or further system compromise.

## Attack Chain

1. An attacker authenticates to the MantisBT application with valid credentials.
2. The attacker navigates to the user account settings page.
3. Within the account settings, the attacker locates the font family preference option.
4. The attacker injects a malicious HTML payload into the font family field, such as `<img src=x onerror=alert(document.domain)>`.
5. The attacker saves the modified account settings.
6. The MantisBT application stores the malicious payload in the database.
7. When the attacker, or any other user, navigates to any page within the MantisBT application, the stored payload is reflected in the HTML output due to the XSS vulnerability.
8. The injected script executes in the victim's browser. Combined with a CSP bypass, the attacker gains the ability to steal cookies or redirect the user to a malicious site, ultimately leading to account takeover.

## Impact

The successful exploitation of this XSS vulnerability, particularly when combined with the CSP bypass, could lead to account takeover. An attacker could gain unauthorized access to sensitive project information, modify bug reports, or escalate privileges within the MantisBT system. The impact is especially severe given the role of MantisBT in managing critical software development processes. The number of potentially affected MantisBT installations is unknown, but this could be significant given the widespread use of MantisBT in software development organizations.

## Recommendation

*   Upgrade MantisBT to a version that includes the patch (9e8409cdd979eba86ef532756fc47c1d8112d22d) to remediate CVE-2026-40596.
*   Deploy the Sigma rule "Detect MantisBT XSS Attempt via User Profile Update" to detect attempts to inject malicious code via the font family field.
*   Investigate any suspicious modifications to user account settings, focusing on the font family preference. Review webserver logs for unusual POST requests to user profile update endpoints.
*   Monitor for exploitation of the CSP bypass vulnerability ([GHSA-9c3j-xm6v-j7j3](https://github.com/mantisbt/mantisbt/security/advisories/GHSA-9c3j-xm6v-j7j3)) to identify potential account takeover attempts.
