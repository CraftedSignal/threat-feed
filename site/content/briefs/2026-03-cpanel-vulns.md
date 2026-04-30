---
title: Multiple Vulnerabilities in cPanel/WHM
slug: 2026-03-cpanel-vulns
description: An anonymous remote attacker can exploit multiple vulnerabilities in cPanel/WHM to bypass security measures, perform XSS and SSRF attacks, disclose information, and potentially execute code.
date: "2026-03-24T12:11:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cPanel
  - WHM
  - XSS
  - SSRF
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0835
rules:
  - title: Detect Suspicious cPanel/WHM HTTP Request
    description: Detects suspicious HTTP requests to cPanel/WHM servers that may indicate SSRF attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect cPanel/WHM XSS Attempt
    description: Detects potential XSS payloads being injected into cPanel/WHM.
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

Multiple vulnerabilities have been identified in cPanel/WHM, a widely used web hosting control panel. An anonymous, remote attacker can exploit these vulnerabilities to compromise cPanel/WHM installations. The vulnerabilities allow an attacker to bypass security measures, perform Cross-Site Scripting (XSS) and Server-Side Request Forgery (SSRF) attacks, disclose sensitive information, and potentially execute arbitrary code on the server. These vulnerabilities pose a significant risk to organizations relying on cPanel/WHM for web hosting, potentially leading to data breaches, service disruption, and unauthorized access to sensitive systems.

## Attack Chain

1.  The attacker identifies a vulnerable cPanel/WHM instance exposed to the internet.
2.  The attacker crafts a malicious HTTP request exploiting an identified SSRF vulnerability to probe internal network resources.
3.  Successful SSRF exploitation allows the attacker to identify internal services and gather information about the server architecture.
4.  The attacker leverages an XSS vulnerability by injecting malicious JavaScript code into a cPanel/WHM page.
5.  Unsuspecting users interacting with the compromised page execute the attacker's JavaScript code.
6.  The attacker uses the XSS payload to steal user session cookies or credentials.
7.  The attacker uses the stolen credentials to bypass authentication and gain unauthorized access to cPanel/WHM.
8.  With elevated privileges, the attacker can potentially execute arbitrary code on the server, leading to full system compromise.

## Impact

Successful exploitation of these vulnerabilities can lead to severe consequences. An attacker could gain unauthorized access to sensitive data, including customer databases, configuration files, and source code. XSS attacks could deface websites and phish users. SSRF attacks can expose internal network resources. Remote code execution can lead to complete server takeover and potentially impact a large number of hosted websites and services. This can result in significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious cPanel/WHM HTTP Request` to identify potential SSRF attempts within cPanel/WHM webserver logs.
*   Deploy the Sigma rule `Detect cPanel/WHM XSS Attempt` to detect potential XSS payloads being injected into cPanel/WHM.
*   Closely monitor web server logs for unusual activity originating from cPanel/WHM servers using the `webserver` category.
*   Implement strong input validation and output encoding to prevent XSS attacks.
*   Harden cPanel/WHM configurations to restrict SSRF attack vectors and limit access to internal resources.
