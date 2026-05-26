---
title: Totolink A8000RU Command Injection Vulnerability (CVE-2026-9385)
slug: 2026-05-totolink-rce
description: A remote command injection vulnerability (CVE-2026-9385) exists in the setTracerouteCfg function of the web management interface in Totolink A8000RU 7.1cu.643_b20200521, allowing unauthenticated attackers to execute arbitrary commands on the device.
date: "2026-05-26T13:56:28Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - cve-2026-9385
  - command injection
  - rce
  - totolink
  - router
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
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-9385
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9385
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_332/README.md
  - https://vuldb.com/submit/813431
  - https://vuldb.com/vuln/365348
  - https://vuldb.com/vuln/365348/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9385 Exploitation Attempt via Command Injection
    description: Detects CVE-2026-9385 exploitation — HTTP request targeting the /cgi-bin/cstecgi.cgi endpoint with shell metacharacters in the command parameter, indicating a command injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
  - title: Detect CVE-2026-9385 Post-Exploitation - Suspicious Process Execution
    description: Detects CVE-2026-9385 post-exploitation — creation of reverse shells or other suspicious processes indicative of command execution on a compromised Totolink router.
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

A command injection vulnerability, identified as CVE-2026-9385, has been discovered in Totolink A8000RU router version 7.1cu.643_b20200521. This vulnerability resides in the `setTracerouteCfg` function within the `/cgi-bin/cstecgi.cgi` file, which is part of the device's web management interface. The vulnerability allows a remote, unauthenticated attacker to inject arbitrary operating system commands by manipulating the `command` argument. Public exploits are available, increasing the risk of widespread exploitation. This poses a significant threat to network security as successful exploitation could lead to complete compromise of the affected device and potentially the network it serves.

## Attack Chain

1.  An unauthenticated attacker identifies a Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2.  The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  Within the HTTP request, the attacker injects OS commands into the `command` argument of the `setTracerouteCfg` function.
4.  The web server processes the request and executes the injected OS command.
5.  The attacker gains initial access to the router's operating system.
6.  The attacker may then leverage this access to download and execute further malicious payloads.
7.  The attacker could establish persistence by modifying system configuration files.
8.  Finally, the attacker achieves complete control of the router, potentially using it as a pivot point for further network attacks, data exfiltration, or denial-of-service attacks.

## Impact

Successful exploitation of this vulnerability (CVE-2026-9385) grants the attacker complete control over the affected Totolink A8000RU router. This can lead to a variety of malicious outcomes, including unauthorized access to the network, data theft, denial-of-service attacks, and the use of the compromised router as a botnet node. Given the publicly available exploit, a large number of devices are potentially at risk.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2026-9385 Exploitation Attempt via Command Injection` to identify exploitation attempts against the `setTracerouteCfg` function in web server logs.
*   Deploy the Sigma rule `Detect CVE-2026-9385 Post-Exploitation - Suspicious Process Execution` to detect post-exploitation activity such as reverse shells or unauthorized software installation.
*   Monitor network traffic for unusual outbound connections originating from Totolink A8000RU devices.
