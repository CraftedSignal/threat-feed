---
title: Zyxel WRE6505 v2 Command Injection Vulnerability (CVE-2026-7256)
slug: 2026-05-zyxel-command-injection
description: A command injection vulnerability (CVE-2026-7256) in Zyxel WRE6505 v2 firmware allows an adjacent attacker on the LAN to execute arbitrary OS commands by sending a crafted HTTP request.
date: "2026-05-12T04:18:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command injection
  - zyxel
  - cve-2026-7256
  - network device
vendors:
  - Zyxel
products:
  - WRE6505 v2 firmware version V1.00(ABDV.3)C0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7256
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7256
  - https://www.zyxel.com/global/en/support/end-of-life
rules:
  - title: Detect Zyxel WRE6505 Command Injection Attempt
    description: Detects CVE-2026-7256 exploitation attempt - crafted HTTP requests to CGI program with shell metacharacters
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect Zyxel WRE6505 Unauthorized Access Attempt
    description: Detects unauthorized access attempts to Zyxel WRE6505 management interface from non-local networks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-7256 describes a command injection vulnerability affecting Zyxel WRE6505 v2 devices running firmware version V1.00(ABDV.3)C0. This vulnerability allows an attacker with adjacent network access (i.e., on the same LAN) to execute arbitrary operating system commands on the affected device. The attack vector involves sending a specially crafted HTTP request to the device's CGI program. While the CVE is marked as "UNSUPPORTED WHEN ASSIGNED," the existence of the vulnerability presents a significant risk to organizations using the affected device, as successful exploitation could lead to complete compromise of the device and potentially the internal network.

## Attack Chain

1.  Attacker gains access to the local network (LAN) where the Zyxel WRE6505 v2 device is connected.
2.  Attacker identifies the IP address of the vulnerable Zyxel WRE6505 v2 device.
3.  Attacker crafts a malicious HTTP request containing shell metacharacters or commands in a CGI program parameter.
4.  Attacker sends the crafted HTTP request to the vulnerable CGI program on the Zyxel device.
5.  The vulnerable CGI program fails to properly sanitize the input, allowing the attacker's injected command to be executed.
6.  The Zyxel device executes the attacker-supplied OS command with the privileges of the web server process.
7.  Attacker gains arbitrary code execution on the device.
8.  Attacker can use the compromised device to pivot further into the network, potentially accessing sensitive data or disrupting network operations.

## Impact

Successful exploitation of CVE-2026-7256 allows an attacker to execute arbitrary commands on the Zyxel WRE6505 v2 device. This could enable the attacker to reconfigure the device, steal sensitive information, or use the device as a pivot point to attack other systems on the local network. Given that this is a network device, successful exploitation could lead to a full compromise of the local network segment. The potential impact includes data breaches, service disruption, and further propagation of malicious activity within the network.

## Recommendation

*   Implement network segmentation to limit the blast radius of a compromised device.
*   Monitor network traffic for suspicious HTTP requests targeting Zyxel devices, using the detection rule `Detect Zyxel WRE6505 Command Injection Attempt`.
*   Consider replacing the affected Zyxel WRE6505 v2 devices if a patch is not available, given the "UNSUPPORTED WHEN ASSIGNED" status.
*   Restrict access to the device's management interface to authorized personnel only.
