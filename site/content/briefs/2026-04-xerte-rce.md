---
title: Xerte Online Toolkits Unauthenticated Remote Code Execution via File Upload
slug: 2026-04-xerte-rce
description: Xerte Online Toolkits 3.15 and earlier contain an incomplete input validation vulnerability allowing unauthenticated attackers to upload malicious PHP code with a '.php4' extension, leading to arbitrary operating system command execution on the server.
date: "2026-04-23T12:00:00Z"
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

Xerte Online Toolkits, a platform used for creating online learning materials, is vulnerable to unauthenticated remote code execution (RCE). Specifically, versions 3.15 and earlier contain an incomplete input validation vulnerability within the elFinder connector endpoint. This flaw allows an attacker to bypass existing file extension filters and upload PHP files with a '.php4' extension. Combined with authentication bypass and path traversal vulnerabilities, this can lead to arbitrary…
