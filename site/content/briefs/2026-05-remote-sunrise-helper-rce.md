---
title: Remote Sunrise Helper for Windows 2026.14 Remote Code Execution Vulnerability
slug: 2026-05-remote-sunrise-helper-rce
description: A remote code execution vulnerability exists in Remote Sunrise Helper for Windows version 2026.14, which can be exploited without authentication, as demonstrated by a public exploit published on Exploit-DB.
date: "2026-05-15T12:53:11Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - remote-code-execution
  - exploit
  - windows
vendors:
  - rs ltd
products:
  - Remote Sunrise Helper for Windows (2026.14)
affected_os:
  - Windows 10
  - Windows 11
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
references:
  - https://www.exploit-db.com/exploits/52565
rules:
  - title: Detect Remote Sunrise Helper Vulnerability Check
    description: Detects requests to /api/getVersion to check for the Remote Sunrise Helper unauthenticated RCE vulnerability
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
  - title: Detect Remote Sunrise Helper Exploit
    description: Detects exploitation of Remote Sunrise Helper RCE vulnerability via the /api/executeScript endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

A remote code execution vulnerability has been identified in Remote Sunrise Helper for Windows 2026.14. A public exploit (EDB-52565) demonstrating the vulnerability has been published on Exploit-DB, indicating a heightened risk for systems running the vulnerable software. The exploit targets the application's API endpoints to execute arbitrary commands on the host. Successful exploitation allows an unauthenticated attacker to execute commands on the targeted Windows system.

## Attack Chain

1.  Attacker identifies a vulnerable Remote Sunrise Helper instance running on a Windows host.
2.  The attacker sends a GET request to `/api/getVersion` to the target on port 49762 to verify the application version and check if authentication is disabled.
3.  The application responds with a JSON object indicating the version and the value of `requires.auth`. If `requires.auth` is `False`, the system is vulnerable.
4.  The attacker crafts a POST request to `/api/executeScript` with the `X-Script` header containing the command to execute.
5.  The attacker sets the `X-HostName`, `X-ClientToken`, and `X-HostFullModel` headers.
6.  The vulnerable application executes the command specified in the `X-Script` header.
7.  The application returns the result of the executed command in JSON format.
8.  The attacker gains remote code execution on the Windows host, potentially leading to further compromise.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary code on the affected Windows system. This could lead to complete system compromise, including data theft, installation of malware, or denial of service. The availability of a public exploit makes this vulnerability highly accessible to attackers.

## Recommendation

*   Apply appropriate mitigations to prevent unauthorized access to port 49762 used by Remote Sunrise Helper.
*   Deploy the Sigma rule `Detect Remote Sunrise Helper Vulnerability Check` to identify systems potentially probing for the vulnerability.
*   Deploy the Sigma rule `Detect Remote Sunrise Helper Exploit` to detect exploit attempts against the `/api/executeScript` endpoint.
*   Monitor web server logs for POST requests to `/api/executeScript` with suspicious `X-Script` headers.
