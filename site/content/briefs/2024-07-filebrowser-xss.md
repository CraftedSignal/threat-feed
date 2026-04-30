---
title: File Browser Stored XSS via Crafted EPUB File
slug: 2024-07-filebrowser-xss
description: File Browser version 2.62.1 and earlier is vulnerable to stored cross-site scripting (XSS) via crafted EPUB files, allowing attackers to execute arbitrary JavaScript in a victim's browser by exploiting the application's misconfigured iframe sandbox and stealing sensitive information like JWT tokens.
date: "2026-03-31T23:44:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - filebrowser
  - xss
  - epub
  - cve-2026-34529
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Local Account
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2024-35236
    cvss: 4.8
    epss: 0.01425
references:
  - https://github.com/advisories/GHSA-5vpr-4fgw-f69h
iocs:
  - type: url
    value: https://attacker.example/?stolen=
  - type: url
    value: https://ifconfig.me/ip
ioc_counts:
  url: 2
rules:
  - title: Detect File Browser EPUB XSS Attempt
    description: Detects attempts to exploit the File Browser EPUB XSS vulnerability by monitoring for network connections to ifconfig.me from the File Browser process, which is used to obtain the victim's IP address.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect File Browser JWT Exfiltration
    description: Detects potential JWT token exfiltration attempts in File Browser by monitoring for network connections to attacker.example with the stolen parameter.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1041
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

File Browser, a web-based file management application, is susceptible to stored XSS attacks in versions 2.62.1 and earlier. The vulnerability stems from the application's EPUB preview functionality, which allows scripted content (`allowScriptedContent: true`) to execute within an iframe.  The iframe's sandbox is misconfigured, including both `allow-scripts` and `allow-same-origin`, effectively bypassing the intended security restrictions. An attacker can upload a specially crafted EPUB file containing malicious JavaScript code. When a user previews the file, the embedded JavaScript executes in their browser, enabling session hijacking via JWT token theft, data exfiltration, and potential privilege escalation if the victim is an administrator.  This vulnerability is similar to CVE-2024-35236 found in audiobookshelf, highlighting a recurring pattern of insecure EPUB handling.

## Attack Chain

1.  An attacker crafts a malicious EPUB file containing embedded JavaScript designed to steal JWT tokens and exfiltrate data.
2.  The attacker authenticates to the File Browser application with a valid, potentially low-privilege, user account.
3.  The attacker uploads the malicious EPUB file to the File Browser server via the `/api/resources` endpoint, potentially overwriting existing files using the `override=true` parameter.
4.  The server stores the malicious EPUB file.
5.  A victim, potentially an administrator, views the uploaded EPUB file through the File Browser's web interface, triggering the EPUB preview function.
6.  The application renders the EPUB file within an iframe. Due to the `allowScriptedContent` setting and misconfigured sandbox, the embedded JavaScript executes.
7.  The JavaScript steals the victim's JWT token from `window.parent.localStorage` and exfiltrates it to an attacker-controlled server (`https://attacker.example/?stolen=`). It may also attempt to gather additional information, such as the victim's public IP address by requesting `https://ifconfig.me/ip`.
8.  The attacker uses the stolen JWT token to hijack the victim's session, potentially gaining administrative privileges.

## Impact

Successful exploitation of this XSS vulnerability allows attackers to steal JWT tokens, leading to full session hijacking and potential privilege escalation. A low-privilege user with upload permissions can compromise administrator accounts. This can lead to unauthorized access to sensitive files, data exfiltration, and modification or deletion of critical data. The vulnerability affects File Browser instances version 2.62.1 and earlier.

## Recommendation

*   Apply patches or upgrade File Browser to a version greater than 2.62.1 to mitigate CVE-2026-34529.
*   Deploy the Sigma rule `Detect File Browser EPUB XSS Attempt` to identify potential exploitation attempts by monitoring for network connections to `ifconfig.me` originating from the File Browser application.
*   Deploy the Sigma rule `Detect File Browser JWT Exfiltration` to detect potential exfiltration of JWT tokens by monitoring network connections to `attacker.example` with a `stolen` parameter.
*   Disable EPUB preview functionality or sanitize EPUB files before rendering them to prevent the execution of malicious scripts. This addresses the root cause by preventing attacker-controlled JavaScript execution.
*   Review and harden the iframe sandbox configuration used for EPUB previews to restrict access to sensitive resources and prevent script execution, if preview functionality cannot be disabled.
