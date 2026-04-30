---
title: Xerte Online Toolkits Unauthenticated Remote Code Execution via File Upload
slug: 2026-04-xerte-rce
description: Xerte Online Toolkits 3.15 and earlier contain an incomplete input validation vulnerability allowing unauthenticated attackers to upload malicious PHP code with a '.php4' extension, leading to arbitrary operating system command execution on the server.
date: "2026-04-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-34415
  - rce
  - file-upload
  - web-application
vendors:
  - Xerte
products:
  - Online Toolkits (<= 3.15)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34415
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34415
  - https://github.com/thexerteproject/xerteonlinetoolkits/commit/02661be88cc369325ea01b508086bde7fbfec805
  - https://github.com/thexerteproject/xerteonlinetoolkits/commit/17e4f945fe6a3400fa88c01eda18c1075ee4a212
  - https://github.com/thexerteproject/xerteonlinetoolkits/commit/507d55c5e91bf9310b5b1c7fad8aebfef902ad23
  - https://github.com/thexerteproject/xerteonlinetoolkits/issues/1527
  - https://www.vulncheck.com/advisories/xerte-online-toolkits-file-upload-rce-via-elfinder-connector
  - https://xerte.org.uk/index.php/en/downloads-1/category/3-xerte-online-toolkits
  - https://xerte.org.uk/xertetoolkits_3.15_ChangeLog.html
rules:
  - title: Detect Suspicious PHP4 Uploads
    description: Detects HTTP requests indicative of attempts to upload PHP files with the '.php4' extension, potentially exploiting CVE-2026-34415.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Suspicious PHP4 Files
    description: Detects HTTP requests to access PHP files with the '.php4' extension after a possible upload attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Xerte Online Toolkits, a platform used for creating online learning materials, is vulnerable to unauthenticated remote code execution (RCE). Specifically, versions 3.15 and earlier contain an incomplete input validation vulnerability within the elFinder connector endpoint. This flaw allows an attacker to bypass existing file extension filters and upload PHP files with a '.php4' extension. Combined with authentication bypass and path traversal vulnerabilities, this can lead to arbitrary operating system command execution on the underlying server. This vulnerability, identified as CVE-2026-34415, poses a significant risk to organizations using affected versions of Xerte Online Toolkits, potentially allowing attackers to gain complete control of the web server.

## Attack Chain

1.  An unauthenticated attacker sends a crafted HTTP request to the elFinder connector endpoint.
2.  The attacker exploits an authentication bypass vulnerability to gain unauthorized access to file upload functionality.
3.  The attacker leverages a path traversal vulnerability to specify a writable directory for the uploaded file.
4.  The attacker uploads a malicious PHP file disguised with a '.php4' extension, bypassing the incomplete input validation.
5.  The server saves the malicious PHP file to the specified directory.
6.  The attacker sends another HTTP request to directly access the uploaded PHP file via its URL.
7.  The web server executes the PHP code within the uploaded file, granting the attacker arbitrary code execution.
8.  The attacker can now execute operating system commands on the server, potentially leading to data theft, system compromise, or further malicious activities.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary operating system commands on the affected Xerte Online Toolkits server. Given the high CVSS score of 9.8, this vulnerability is considered critical. If exploited, an attacker could potentially gain full control of the server, leading to data breaches, defacement of the website, or the use of the compromised server as a launchpad for further attacks within the network. The number of potentially affected installations is currently unknown.

## Recommendation

*   Upgrade Xerte Online Toolkits to a patched version greater than 3.15 to remediate CVE-2026-34415.
*   Implement the Sigma rule "Detect Suspicious PHP4 Uploads" to identify potential exploitation attempts by monitoring web server logs for '.php4' file uploads.
*   Review web server access logs for unusual requests to PHP files located in unexpected directories, which may indicate exploitation attempts.
*   Monitor web server logs for requests to the elFinder connector endpoint that include suspicious parameters or file extensions.
