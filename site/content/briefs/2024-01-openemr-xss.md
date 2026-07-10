---
title: OpenEMR Stored Cross-Site Scripting Vulnerability (CVE-2026-33348)
slug: 2024-01-openemr-xss
description: A stored cross-site scripting (XSS) vulnerability exists in OpenEMR versions prior to 8.0.0.3, allowing an authenticated attacker with the `Notes - my encounters` role to inject arbitrary JavaScript that is executed when other users with the same role view patient encounter pages or visit history.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openemr
  - xss
  - cve-2026-33348
  - web-application
vendors:
  - OpenEMR
products:
  - OpenEMR
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33348
rules:
  - title: Detect OpenEMR XSS Attempt via URI
    description: Detects potential XSS attempts in OpenEMR by looking for script tags or event handlers in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect OpenEMR XSS Attempt via POST Request
    description: Detects potential XSS attempts in OpenEMR via POST requests by looking for script tags or event handlers in the request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenEMR, a widely used open-source electronic health records and medical practice management application, is vulnerable to a stored cross-site scripting (XSS) attack. This vulnerability affects versions prior to 8.0.0.3. An attacker who has already authenticated with the `Notes - my encounters` role can inject malicious JavaScript code into the system via the 'Eye Exam' forms within patient encounters. The injected script executes when other users with the same role view the affected patient encounter page or visit history. This vulnerability, identified as CVE-2026-33348, allows for potential data theft, session hijacking, or defacement of the OpenEMR application. Organizations using OpenEMR should upgrade to version 8.0.0.3 or later immediately to mitigate this risk.

## Attack Chain

1.  Attacker authenticates to the OpenEMR application with the `Notes - my encounters` role.
2.  Attacker navigates to the 'Eye Exam' form within a patient encounter.
3.  Attacker enters a malicious JavaScript payload into one or more of the form fields. Example payload: `<script>alert('XSS')</script>` or `<img src=x onerror=prompt(1)>`.
4.  The malicious payload is saved to the OpenEMR database as part of the form submission.
5.  Another user authenticates to OpenEMR with the `Notes - my encounters` role.
6.  The user views the patient encounter page or visit history containing the attacker's injected payload.
7.  The injected JavaScript code is executed within the user's browser, potentially performing actions on behalf of the user.
8.  The attacker could steal sensitive information, modify data, or redirect the user to a malicious website.

## Impact

Successful exploitation of this XSS vulnerability could allow an attacker to compromise the confidentiality, integrity, and availability of OpenEMR data. This could lead to unauthorized access to patient records, modification of medical information, or disruption of clinical workflows. Given the sensitivity of healthcare data, a successful attack could have serious legal and reputational consequences. The number of potential victims depends on the number of OpenEMR installations affected and the number of users with the `Notes - my encounters` role.

## Recommendation

*   Upgrade OpenEMR to version 8.0.0.3 or later to patch CVE-2026-33348.
*   Deploy the Sigma rule `Detect OpenEMR XSS Attempt via URI` to detect potential exploitation attempts on the webserver.
*   Implement input validation and output encoding on all user-supplied data to prevent future XSS vulnerabilities.
*   Educate users with the `Notes - my encounters` role about the risks of XSS attacks and the importance of reporting suspicious behavior.
