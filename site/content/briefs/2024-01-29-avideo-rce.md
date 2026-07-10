---
title: WWBN AVideo Unauthenticated Remote Code Execution via CSRF
slug: 2024-01-29-avideo-rce
description: WWBN AVideo versions up to 26.0 are vulnerable to remote code execution, where an unauthenticated attacker can exploit a CSRF vulnerability in the `objects/pluginImport.json.php` endpoint to upload a malicious plugin containing a PHP webshell due to the application setting `session.cookie_samesite = 'None'`.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - rce
  - csrf
  - php
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33507
rules:
  - title: Detect AVideo Plugin Upload Attempt
    description: Detects attempts to upload plugins via the objects/pluginImport.json.php endpoint, potentially indicating exploitation of the CSRF vulnerability (CVE-2026-33507).
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Potential Webshell Access
    description: Detects access to common PHP webshell file extensions after plugin upload, indicating successful exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is susceptible to a critical unauthenticated remote code execution (RCE) vulnerability (CVE-2026-33507) in versions up to and including 26.0. The vulnerability resides within the `objects/pluginImport.json.php` endpoint, which allows administrative users to upload and install plugin ZIP files. However, this endpoint lacks Cross-Site Request Forgery (CSRF) protection. The application further exacerbates the issue by explicitly setting `session.cookie_samesite = 'None'` for HTTPS connections. This configuration allows an unauthenticated attacker to craft a malicious web page that, when visited by a logged-in administrator, silently uploads a malicious plugin containing a PHP webshell. Successful exploitation grants the attacker arbitrary code execution on the affected server. A patch is available in commit d1bc1695edd9ad4468a48cea0df6cd943a2635f3. This vulnerability poses a significant risk to organizations using vulnerable AVideo instances, potentially leading to complete system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable AVideo instance running a version up to 26.0.
2.  The attacker crafts a malicious plugin ZIP file containing a PHP webshell. This plugin is designed to execute arbitrary commands when installed.
3.  The attacker creates a malicious web page containing a CSRF exploit. This page includes a form that automatically submits a request to the `objects/pluginImport.json.php` endpoint. The request is designed to upload the malicious plugin.
4.  The attacker lures an authenticated AVideo administrator to visit the malicious web page. This can be achieved through social engineering tactics.
5.  When the administrator visits the page, the CSRF exploit silently submits the form to the vulnerable endpoint. Because `session.cookie_samesite` is set to 'None', the administrator's session cookie is sent along with the request, bypassing authentication checks that might otherwise prevent the unauthorized plugin upload.
6.  The AVideo server processes the request and installs the malicious plugin.
7.  The attacker accesses the PHP webshell through a web browser, typically by navigating to a specific URL associated with the installed plugin.
8.  The attacker executes arbitrary commands on the server, gaining full control of the AVideo instance. This can lead to data exfiltration, service disruption, or further malicious activities.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to achieve remote code execution on the AVideo server. This can lead to complete system compromise, including the ability to read and modify sensitive data, install malware, and disrupt video services. The lack of CSRF protection coupled with the `session.cookie_samesite = 'None'` setting makes this vulnerability particularly dangerous. While the exact number of affected AVideo instances is unknown, the open-source nature of the platform suggests a potentially wide user base, increasing the scope of potential victims. Organizations running vulnerable AVideo instances are at risk of data breaches, financial loss, and reputational damage.

## Recommendation

*   Upgrade AVideo instances to a version containing the patch from commit d1bc1695edd9ad4468a48cea0df6cd943a2635f3 to address the CSRF vulnerability.
*   Monitor web server logs for POST requests to the `objects/pluginImport.json.php` endpoint (see rule: "Detect AVideo Plugin Upload Attempt") and investigate any unexpected activity.
*   Implement proper CSRF protection measures in AVideo, if possible, to prevent unauthorized plugin uploads.
*   Review and restrict administrative access to AVideo instances to minimize the attack surface.
*   Enable webserver logging and deploy the Sigma rules in this brief to your SIEM and tune for your environment.
