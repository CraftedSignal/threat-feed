---
title: Totolink A8000RU Command Injection Vulnerability (CVE-2026-9458)
slug: 2026-05-totolink-command-injection
description: A remote command injection vulnerability (CVE-2026-9458) exists in the setWanCfg function of the /cgi-bin/cstecgi.cgi file within the Web Management Interface of Totolink A8000RU version 7.1cu.643_b20200521, allowing unauthenticated attackers to execute arbitrary OS commands.
date: "2026-05-26T14:03:47Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - command-injection
  - network-device
  - cve
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-9458
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9458
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_346/README.md
  - https://vuldb.com/submit/813457
  - https://vuldb.com/vuln/365439
  - https://vuldb.com/vuln/365439/cti
  - https://www.totolink.net/
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt via setWanCfg
    description: Detects CVE-2026-9458 exploitation — HTTP POST to /cgi-bin/cstecgi.cgi with shell metacharacters in the query string targeting the setWanCfg function, indicating a command injection attempt
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
  - title: Detect Totolink A8000RU Suspicious Process Creation
    description: Detects suspicious process creation events originating from the web server process, potentially indicating command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical command injection vulnerability, identified as CVE-2026-9458, affects Totolink A8000RU routers running firmware version 7.1cu.643_b20200521. The vulnerability resides in the `setWanCfg` function within the `/cgi-bin/cstecgi.cgi` file, part of the Web Management Interface. Publicly available exploits demonstrate that by manipulating the `enabled` argument, a remote, unauthenticated attacker can inject and execute arbitrary operating system commands on the device. This vulnerability poses a significant risk as it allows complete compromise of the router and potentially the network it serves.

## Attack Chain

1.  The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
2.  The request targets the `setWanCfg` function.
3.  The attacker injects malicious OS commands into the `enabled` argument of the `setWanCfg` function.
4.  The webserver processes the request without proper sanitization.
5.  The `setWanCfg` function executes the injected OS commands with elevated privileges.
6.  The attacker gains arbitrary code execution on the router's operating system.
7.  The attacker may then install malware, change router configurations, or use the router as a pivot point for further attacks within the network.
8.  The attacker achieves full control of the device, potentially leading to data exfiltration or denial of service.

## Impact

Successful exploitation of CVE-2026-9458 allows a remote, unauthenticated attacker to execute arbitrary operating system commands on the affected Totolink A8000RU router. This can lead to complete compromise of the device, including the ability to modify router configurations, install malware, intercept network traffic, and pivot to other devices on the network. Given the high CVSS score of 9.8, this vulnerability poses a critical risk to home and small business networks using the affected router model and firmware version.

## Recommendation

*   Apply available firmware updates from Totolink to patch CVE-2026-9458.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` with shell metacharacters in the query string, as detected by the "Detect Totolink A8000RU Command Injection Attempt via setWanCfg" Sigma rule.
*   Implement network intrusion detection systems (IDS) to identify and block exploitation attempts targeting this vulnerability.
*   Disable remote access to the router's web management interface if it is not required.
