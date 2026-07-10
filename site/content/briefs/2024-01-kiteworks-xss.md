---
title: Kiteworks Secure Data Forms Stored XSS Vulnerability (CVE-2026-24750)
slug: 2024-01-kiteworks-xss
description: An authenticated attacker can exploit a stored XSS vulnerability (CVE-2026-24750) in Kiteworks Secure Data Forms before version 9.2.1 due to improper neutralization of input, leading to arbitrary script execution in the context of other users.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - web-application
  - kiteworks
vendors:
  - Kiteworks
products:
  - Kiteworks Secure Data Forms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24750
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Kiteworks Form Modification
    description: Detects potential XSS injection attempts in HTTP requests to the Kiteworks server by looking for script tags or event handlers in form modification requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Kiteworks Form Modification - Encoded Payload
    description: Detects potential XSS injection attempts in HTTP requests to the Kiteworks server by looking for encoded script tags or event handlers in form modification requests. This will catch obfuscated attacks.
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

Kiteworks is a private data network (PDN) platform, and versions of Kiteworks Secure Data Forms prior to 9.2.1 are vulnerable to a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-24750). This vulnerability allows an authenticated attacker to inject malicious scripts into data forms. When other users view or interact with the modified form, the injected script executes in their browser. This could lead to session hijacking, sensitive data theft, or other malicious activities. Organizations using vulnerable versions of Kiteworks are at risk of unauthorized access and data breaches. The vulnerability arises from a failure to properly sanitize user-supplied input during web page generation.

## Attack Chain

1.  The attacker authenticates to the Kiteworks Secure Data Forms application.
2.  The attacker identifies a form that allows modification.
3.  The attacker injects a malicious JavaScript payload into a form field. This payload is crafted to be stored in the application's database.
4.  The application saves the form with the malicious payload into its database.
5.  A different user, or an administrator, accesses the modified form through the Kiteworks web interface.
6.  The web application retrieves the form data, including the malicious JavaScript payload, from the database.
7.  The application renders the form in the user's browser without properly sanitizing the data.
8.  The malicious JavaScript code executes in the user's browser, potentially stealing cookies, redirecting the user to a phishing site, or performing other unauthorized actions.

## Impact

Successful exploitation of CVE-2026-24750 can lead to several adverse outcomes. An attacker could potentially gain access to sensitive data stored within the Kiteworks platform, compromise user accounts, and perform actions on behalf of other users. The impact ranges from data theft to complete compromise of the Kiteworks installation. Organizations in any sector using vulnerable Kiteworks installations may be affected. This vulnerability allows attackers to move laterally within the application and potentially escalate privileges.

## Recommendation

*   Upgrade Kiteworks to version 9.2.1 or later to patch CVE-2026-24750.
*   Implement and deploy the Sigma rule `Detect Suspicious Kiteworks Form Modification` to detect potential XSS injection attempts in HTTP requests to the Kiteworks server.
*   Monitor web server logs for unusual patterns in requests to form modification endpoints, specifically looking for `<script>` tags or JavaScript event handlers, to identify potential exploitation attempts (webserver log source).
*   Review and audit existing Kiteworks Secure Data Forms for any unexpected or suspicious content that may indicate prior exploitation.
