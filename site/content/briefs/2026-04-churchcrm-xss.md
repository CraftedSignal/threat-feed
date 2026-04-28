---
title: ChurchCRM Stored XSS Vulnerability (CVE-2026-35574)
slug: 2026-04-churchcrm-xss
description: A stored XSS vulnerability in ChurchCRM versions before 6.5.3 allows authenticated users with note-adding permissions to inject arbitrary JavaScript code, potentially leading to session hijacking and privilege escalation.
date: "2026-04-07T17:16:32Z"
severities:
  - high
tags:
  - cve-2026-35574
  - xss
  - churchcrm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35574
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35574
  - https://github.com/ChurchCRM/CRM/security/advisories/GHSA-cx82-8xrh-7f5c
iocs:
  - type: url
    value: https://github.com/ChurchCRM/CRM/security/advisories/GHSA-cx82-8xrh-7f5c
ioc_counts:
  url: 1
rules:
  - title: Detect ChurchCRM XSS via Note Editor
    description: Detects potential XSS attacks against ChurchCRM Note Editor by looking for script tags or event handlers in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ChurchCRM XSS via Note Editor - URL Encoded
    description: Detects potential XSS attacks against ChurchCRM Note Editor with URL encoded javascript in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ChurchCRM, an open-source church management system, is vulnerable to a stored Cross-Site Scripting (XSS) flaw. This vulnerability, identified as CVE-2026-35574, resides in the Note Editor of versions prior to 6.5.3. Authenticated users possessing note-adding permissions can inject malicious JavaScript code into notes. When other users, including administrators, view these notes, the injected script executes within their browsers. This can result in session hijacking, privilege escalation, and unauthorized access to sensitive data contained within the ChurchCRM system. Users are advised to upgrade to version 6.5.3 to mitigate this risk.

## Attack Chain

1. An attacker logs into ChurchCRM with a valid user account that has note-adding permissions.
2. The attacker navigates to the Note Editor within the ChurchCRM application.
3. The attacker crafts a malicious payload containing JavaScript code designed to steal session cookies or redirect the user to a phishing site.
4. The attacker injects the malicious payload into a new or existing note.
5. The attacker saves the note, which stores the malicious payload in the ChurchCRM database.
6. A victim user, such as an administrator, views the note containing the injected XSS payload.
7. The victim's browser executes the malicious JavaScript code from the note.
8. The attacker gains unauthorized access to the victim's session or sensitive data, leading to potential privilege escalation or data theft.

## Impact

Successful exploitation of this XSS vulnerability could allow an attacker to hijack administrator sessions, potentially leading to complete control over the ChurchCRM system. Sensitive church member data, including personal information, financial records, and contact details, could be accessed and exfiltrated. The number of potential victims depends on the number of ChurchCRM users and the extent of the attacker's access following a successful session hijack.

## Recommendation

*   Upgrade ChurchCRM to version 6.5.3 or later to patch CVE-2026-35574.
*   Deploy the Sigma rule "Detect ChurchCRM XSS via Note Editor" to identify potential exploitation attempts in web server logs.
*   Implement input validation and output encoding on the Note Editor to prevent XSS attacks.
