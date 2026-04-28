---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-6154)
slug: 2026-04-totolink-command-injection
description: CVE-2026-6154 is a critical vulnerability in Totolink A7100RU firmware that allows remote attackers to inject OS commands by manipulating the 'wizard' argument in the setWizardCfg function, leading to potential system compromise.
date: "2026-04-13T04:16:14Z"
severities:
  - critical
tags:
  - cve-2026-6154
  - command-injection
  - totolink
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6154
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6154
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_194/README.md
  - https://vuldb.com/vuln/357034
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects attempts to exploit the Totolink A7100RU command injection vulnerability (CVE-2026-6154) by looking for suspicious POST requests to the cstecgi.cgi endpoint with shell commands in the wizard argument.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Command Injection Successful
    description: Detects a successful exploitation of the Totolink A7100RU command injection vulnerability (CVE-2026-6154) by looking for evidence of command execution in web server logs after a suspicious POST to the cstecgi.cgi endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical OS command injection vulnerability, CVE-2026-6154, affects Totolink A7100RU devices running firmware version 7.4cu.2313_b20191024. The vulnerability resides in the `setWizardCfg` function within the `/cgi-bin/cstecgi.cgi` CGI handler. By manipulating the `wizard` argument, a remote, unauthenticated attacker can inject and execute arbitrary OS commands on the affected device. Publicly available exploits exist, increasing the risk of widespread exploitation. This vulnerability poses a significant threat as it allows attackers to gain complete control of the router, potentially leading to data exfiltration, denial of service, or further network compromise.

## Attack Chain

1.  Attacker identifies a vulnerable Totolink A7100RU router running firmware 7.4cu.2313_b20191024.
2.  Attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The crafted request includes a `wizard` argument containing an OS command injection payload.
4.  The `setWizardCfg` function processes the `wizard` argument without proper sanitization.
5.  The injected OS command is executed with the privileges of the web server process.
6.  The attacker gains the ability to execute arbitrary commands on the system.
7.  The attacker may install malware, change router settings, or exfiltrate sensitive information.
8.  The attacker can use the compromised router as a pivot point for further attacks within the network.

## Impact

Successful exploitation of CVE-2026-6154 allows a remote attacker to execute arbitrary OS commands on the affected Totolink A7100RU device. This can lead to complete compromise of the router, enabling attackers to modify settings, intercept network traffic, launch further attacks within the local network, or use the router as part of a botnet. Given the widespread use of Totolink routers, a large number of devices are potentially vulnerable, impacting both home and small business networks.

## Recommendation

*   Apply the Sigma rule `Detect Totolink A7100RU Command Injection Attempt` to identify exploitation attempts in web server logs.
*   Apply the Sigma rule `Detect Totolink A7100RU Command Injection Successful` to identify successful exploitation in web server logs.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` containing shell commands in the `wizard` argument.
*   Implement network segmentation to limit the impact of a compromised router on other network devices.
*   Consider blocking or rate-limiting access to `/cgi-bin/cstecgi.cgi` from untrusted networks.
