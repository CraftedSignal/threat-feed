---
title: FUXA 1.2.8 Authentication Bypass and Remote Command Execution Vulnerability
slug: 2024-01-fuxa-rce
description: FUXA 1.2.8 and earlier is vulnerable to an authentication bypass vulnerability (CVE-2025-69985) that allows remote command execution by exploiting the /api/runscript endpoint with a crafted JavaScript payload.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - remote-code-execution
  - web-application
  - scada
vendors:
  - frangoteam
products:
  - FUXA (<= 1.2.8)
affected_os:
  - Debian GNU/Linux 12
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: JavaScript'
cves:
  - id: CVE-2025-69985
    cvss: 9.8
    epss: 0.04692
references:
  - https://www.exploit-db.com/exploits/52544
rules:
  - title: Detect FUXA API Runscript Exploitation
    description: Detects requests to the /api/runscript endpoint in FUXA, which is vulnerable to authentication bypass and RCE (CVE-2025-69985)
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Javascript in FUXA API Runscript
    description: Detects suspicious JavaScript code within requests to the /api/runscript endpoint, indicative of RCE attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FUXA, a web-based SCADA/HMI software, versions 1.2.8 and earlier, contains an authentication bypass vulnerability (CVE-2025-69985). This vulnerability allows unauthenticated attackers to execute arbitrary commands on the server by exploiting the `/api/runscript` endpoint. The exploit uses a crafted JavaScript payload leveraging `child_process.execSync` to execute commands, capturing the full standard output. This vulnerability was discovered and published in February 2026 by Joshua van der Poll, and a proof-of-concept exploit is publicly available. Successful exploitation leads to complete system compromise, emphasizing the critical need for patching and detection measures. The vulnerability has been patched in versions of FUXA greater than 1.2.8.

## Attack Chain

1. An unauthenticated attacker sends a POST request to `/api/runscript`.
2. The attacker crafts a JSON payload containing a `script` parameter with malicious JavaScript code.
3. The JavaScript code utilizes the `child_process.execSync` function to execute arbitrary commands on the system.
4. The `execSync` function captures the standard output and standard error of the executed command.
5. The captured output is returned in the HTTP response.
6. The attacker parses the HTTP response to retrieve the output of the executed command.
7. The attacker can then use the command execution to perform further actions, such as reading sensitive files, installing malware, or creating new user accounts.
8. The attacker achieves full remote command execution, potentially leading to complete system compromise.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary commands on the FUXA server. This can lead to complete system compromise, including data theft, service disruption, and the installation of malware. Given the nature of SCADA/HMI software, this could have significant consequences for industrial control systems and critical infrastructure. While specific victim numbers are unavailable, the potential impact is high due to the critical nature of the targeted software.

## Recommendation

*   Upgrade FUXA to a version greater than 1.2.8 to patch CVE-2025-69985.
*   Deploy the Sigma rule "Detect FUXA API Runscript Exploitation" to your SIEM to identify exploitation attempts against the `/api/runscript` endpoint.
*   Monitor web server logs for POST requests to `/api/runscript` with unusual or suspicious JavaScript code in the `script` parameter, as detected by the rule "Detect Suspicious Javascript in FUXA API Runscript".
*   Implement network segmentation to limit the blast radius of a potential compromise, isolating FUXA servers from other critical systems.
