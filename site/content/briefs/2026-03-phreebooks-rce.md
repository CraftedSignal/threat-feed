---
title: PhreeBooks ERP 5.2.3 Remote Code Execution Vulnerability
slug: 2026-03-phreebooks-rce
description: PhreeBooks ERP 5.2.3 is vulnerable to remote code execution, allowing authenticated attackers to upload and execute arbitrary PHP files via the image manager, leading to reverse shell connections and system command execution.
date: "2026-03-24T12:16:07Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - rce
  - vulnerability
  - php
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25647
  - https://www.exploit-db.com/exploits/46645
rules:
  - title: Detect Suspicious PHP Upload via Image Manager
    description: Detects attempts to upload PHP files through the image manager by monitoring POST requests with PHP content.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect PHP execution from unusual web paths
    description: Detects PHP execution from unusual web paths, indicating potential RCE exploitation
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

PhreeBooks ERP version 5.2.3 is susceptible to a remote code execution (RCE) vulnerability (CVE-2019-25647) within its image manager component. This flaw enables authenticated attackers to bypass file extension restrictions and upload malicious PHP files. Successful exploitation allows attackers to execute arbitrary code on the underlying server, potentially leading to complete system compromise. The vulnerability exists because the image manager lacks adequate validation of uploaded file types, permitting the upload of PHP files disguised with allowed extensions or lacking extensions altogether. This can lead to reverse shell creation.

## Attack Chain

1. An attacker authenticates to the PhreeBooks ERP 5.2.3 application.
2. The attacker accesses the image manager functionality.
3. The attacker crafts a malicious PHP file designed to execute system commands or establish a reverse shell.
4. The attacker uploads the malicious PHP file through the image manager, bypassing file extension validation. This may involve renaming the file with a permitted extension or omitting the extension entirely.
5. The attacker identifies the upload location of the malicious PHP file.
6. The attacker sends an HTTP request to the uploaded PHP file's location on the server.
7. The web server executes the PHP code, triggering the attacker's malicious payload (e.g., reverse shell).
8. The attacker gains remote access to the server and can execute arbitrary system commands.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the targeted server. This can lead to complete system compromise, including data theft, modification, or destruction. Given that PhreeBooks ERP is used to manage business operations, a successful attack could result in significant financial losses, disruption of services, and reputational damage. There is no specific information about victim count or sectors targeted available from the source.

## Recommendation

*   Apply any available patches or updates for PhreeBooks ERP to address CVE-2019-25647.
*   Implement the Sigma rule "Detect Suspicious PHP Upload via Image Manager" to detect attempts to upload malicious PHP files through the image manager.
*   Monitor web server logs for requests to unusual file paths containing PHP code, as this could indicate exploitation attempts.
*   Restrict access to the image manager functionality to only authorized users.
