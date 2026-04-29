---
title: Cisco Integrated Management Controller (IMC) Multiple XSS Vulnerabilities
slug: 2026-04-cisco-imc-xss
description: Multiple cross-site scripting (XSS) vulnerabilities in the web-based management interface of Cisco Integrated Management Controller (IMC) could allow a remote attacker to conduct an XSS attack against a user of the interface.
date: "2026-04-23T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - xss
  - cisco
  - cimc
  - vulnerability
vendors:
  - Cisco
products:
  - Integrated Management Controller
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-20085
    cvss: 6.1
    epss: 0.00022
  - id: CVE-2026-20087
    cvss: 4.8
    epss: 0.00036
  - id: CVE-2026-20088
    cvss: 4.8
    epss: 0.00036
  - id: CVE-2026-20089
    cvss: 4.8
    epss: 0.00036
  - id: CVE-2026-20090
    cvss: 4.8
    epss: 0.00036
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-xss-A2tkgVAB
rules:
  - title: Detect Suspicious URI Access to Cisco IMC
    description: Detects suspicious URI access patterns to Cisco IMC web interface which might be related to exploitation of XSS vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP Request Containing Script Tags
    description: Detects HTTP requests containing script tags which might indicate XSS attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple cross-site scripting (XSS) vulnerabilities have been identified in the web-based management interface of the Cisco Integrated Management Controller (IMC). Successful exploitation of these vulnerabilities could allow a remote attacker to inject malicious scripts into the web browser of a user accessing the IMC interface. This could lead to session hijacking, sensitive information disclosure, or other malicious activities performed in the context of the user's session. The vulnerabilities were disclosed on 2026-04-22, and Cisco has released software updates to address them. There are no known workarounds. This threat is relevant for organizations using Cisco IMC to manage their infrastructure.

## Attack Chain

1.  Attacker identifies a vulnerable Cisco IMC web interface.
2.  Attacker crafts a malicious URL containing a JavaScript payload designed to execute in the context of a victim's browser session.
3.  Attacker delivers the malicious URL to the victim, typically through phishing, social engineering, or by injecting it into a trusted website.
4.  Victim clicks on the malicious URL, or the URL is automatically loaded through a compromised website.
5.  The victim's web browser sends an HTTP request to the vulnerable Cisco IMC web server.
6.  The Cisco IMC web server reflects the attacker's malicious JavaScript payload in the HTTP response without proper sanitization.
7.  The victim's web browser executes the malicious JavaScript code.
8.  The attacker's JavaScript code executes within the victim's browser, allowing the attacker to steal cookies, redirect the user, or perform other actions on behalf of the victim.

## Impact

Successful exploitation of these XSS vulnerabilities could allow an attacker to execute arbitrary JavaScript code in the context of a user's session. This could lead to sensitive information disclosure, such as the theft of session cookies, allowing the attacker to hijack the user's session and gain unauthorized access to the Cisco IMC. The attacker could also redirect the user to a malicious website or deface the IMC web interface. While the specific number of vulnerable systems is unknown, organizations using Cisco IMC are potentially at risk.

## Recommendation

*   Apply the software updates released by Cisco to address the vulnerabilities (CVE-2026-20085, CVE-2026-20087, CVE-2026-20088, CVE-2026-20089, CVE-2026-20090).
*   Deploy the Sigma rule provided below to detect potential exploitation attempts against the Cisco IMC web interface.
*   Monitor web server logs for suspicious HTTP requests containing potentially malicious JavaScript payloads targeting the Cisco IMC web interface.
