---
title: CVE-2021-47976 - TextPattern CMS Authenticated Remote Code Execution via Plugin Upload
slug: 2026-05-textpattern-rce
description: TextPattern CMS 4.9.0-dev is vulnerable to remote code execution (CVE-2021-47976), allowing authenticated attackers to upload arbitrary PHP files and achieve code execution by exploiting the plugin upload functionality.
date: "2026-05-16T16:22:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - csrf
  - textpattern
vendors:
  - Textpattern
products:
  - TextPattern CMS 4.9.0-dev
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2021-47976
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47976
  - https://github.com/textpattern/textpattern
  - https://textpattern.com/
  - https://www.exploit-db.com/exploits/50095
  - https://www.vulncheck.com/advisories/textpattern-cms-dev-authenticated-remote-code-execution-via-plugin-upload
rules:
  - title: Detect Textpattern CMS PHP Upload via CVE-2021-47976
    description: Detects CVE-2021-47976 exploitation — PHP file upload to /textpattern/tmp/ directory
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CSRF Token Retrieval in Textpattern CMS
    description: Detects retrieval of CSRF token from plugin event page, which can be used in CVE-2021-47976 exploitation
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

TextPattern CMS version 4.9.0-dev is susceptible to a remote code execution (RCE) vulnerability, identified as CVE-2021-47976. This flaw allows authenticated attackers to upload malicious PHP files to the server, leading to arbitrary code execution. The vulnerability resides within the plugin upload functionality. An attacker must first authenticate to the TextPattern CMS application. Once authenticated, the attacker can retrieve a valid CSRF token from the plugin event page. This token is then used in conjunction with the malicious PHP file upload request to bypass CSRF protections, placing the malicious code in the textpattern/tmp/ directory. This vulnerability poses a significant risk to organizations using the affected TextPattern CMS version, potentially leading to complete system compromise.

## Attack Chain

1.  Attacker authenticates to the TextPattern CMS 4.9.0-dev web application.
2.  Attacker navigates to the plugin event page to retrieve a valid CSRF token.
3.  The attacker crafts a malicious PHP file designed to execute arbitrary commands on the server.
4.  The attacker initiates a file upload request targeting the plugin upload functionality.
5.  The attacker includes the retrieved CSRF token within the upload request to bypass CSRF protection mechanisms.
6.  The malicious PHP file is successfully uploaded to the textpattern/tmp/ directory on the server.
7.  The attacker triggers the execution of the uploaded PHP file by accessing it via a web request.
8.  The malicious PHP file executes arbitrary commands on the server, granting the attacker control of the system.

## Impact

Successful exploitation of CVE-2021-47976 can lead to complete compromise of the TextPattern CMS server. An attacker can gain unauthorized access to sensitive data, modify website content, install backdoors, or use the compromised server as a launchpad for further attacks against other systems within the network. Due to the potential for full system compromise, this vulnerability poses a critical risk to organizations utilizing the affected TextPattern CMS version.

## Recommendation

*   Apply any available patches or updates provided by Textpattern to address CVE-2021-47976.
*   Implement the Sigma rule "Detect Textpattern CMS PHP Upload via CVE-2021-47976" to detect attempts to exploit this vulnerability via webserver logs.
*   Monitor web server logs for suspicious file uploads to the /textpattern/tmp/ directory, and cross-reference with authentication events.
*   Review and restrict plugin upload permissions within TextPattern CMS to only authorized administrators.
