---
title: OpenEMR Stored XSS Vulnerability in CCDA Document Preview (CVE-2026-33932)
slug: 2024-01-openemr-xss
description: A stored cross-site scripting (XSS) vulnerability in OpenEMR's CCDA document preview (CVE-2026-33932) allows an attacker to execute arbitrary JavaScript in a clinician's browser session by uploading a malicious CCDA document.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - openemr
  - xss
  - cve-2026-33932
  - health-records
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
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33932
rules:
  - title: Detect Suspicious OpenEMR CCDA Document Preview
    description: 'Detects potential XSS attempts in OpenEMR CCDA document preview requests by looking for javascript: in URI queries.'
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious OpenEMR CCDA Document Upload with Script Tags
    description: Detects potential XSS attempts in OpenEMR CCDA document uploads by looking for script tags in the request body.
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

A stored cross-site scripting (XSS) vulnerability has been identified in OpenEMR, a widely used open-source electronic health records and medical practice management application. Specifically, the vulnerability resides within the CCDA (Consolidated Clinical Document Architecture) document preview feature. Prior to version 8.0.0.3, an attacker with the ability to upload or send a CCDA document can inject malicious JavaScript code. When a clinician previews the booby-trapped document, the injected script executes within their browser session. This is due to insufficient sanitization of the `linkHtml` attribute in the XSL stylesheet used for rendering CCDA documents. The vulnerability, identified as CVE-2026-33932, allows `href="javascript:..."` and event handler attributes to pass through unfiltered. OpenEMR version 8.0.0.3 addresses this critical security flaw.

## Attack Chain

1. An attacker identifies an OpenEMR instance running a vulnerable version (prior to 8.0.0.3).
2. The attacker crafts a malicious CCDA document containing a `linkHtml` attribute with a JavaScript payload, such as `<linkHtml href="javascript:alert('XSS')">`.
3. The attacker uploads the malicious CCDA document to the OpenEMR instance, potentially through patient record upload functionality or direct messaging features.
4. A clinician or authorized user accesses the patient record containing the malicious CCDA document.
5. The clinician previews the CCDA document within the OpenEMR interface.
6. The OpenEMR application processes the CCDA document using the vulnerable XSL stylesheet.
7. Due to the lack of proper sanitization, the JavaScript payload within the `linkHtml` attribute is rendered in the clinician's browser.
8. The JavaScript code executes in the clinician's browser session, potentially allowing the attacker to steal session cookies, redirect the user to a phishing site, or perform other malicious actions within the context of the OpenEMR application.

## Impact

Successful exploitation of this XSS vulnerability can lead to several damaging consequences. An attacker could steal a clinician's session cookies, gaining unauthorized access to sensitive patient data. They could also redirect users to phishing sites to harvest credentials or inject malicious code into the OpenEMR application to compromise its functionality. Given the sensitive nature of electronic health records, a successful attack could result in significant privacy breaches, regulatory violations (HIPAA), and reputational damage to the healthcare provider. While the specific number of affected organizations is unknown, OpenEMR is used by numerous healthcare providers globally, placing a large patient population at risk.

## Recommendation

*   Upgrade OpenEMR to version 8.0.0.3 or later to patch the CVE-2026-33932 vulnerability.
*   Deploy the Sigma rule "Detect Suspicious OpenEMR CCDA Document Preview" to your SIEM and tune for your environment, monitoring webserver logs for requests containing suspicious patterns in the URI.
*   Implement input validation and sanitization measures for all user-supplied data within the OpenEMR application, focusing on CCDA document processing.
*   Educate clinicians and other OpenEMR users about the risks of XSS attacks and the importance of reporting any suspicious activity.
