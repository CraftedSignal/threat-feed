---
title: UniFi Play Command Injection Vulnerability (CVE-2026-22563)
slug: 2026-04-unifi-command-injection
description: A malicious actor with access to the UniFi Play network can exploit improper input validation vulnerabilities (CVE-2026-22563) in UniFi Play PowerAmp and Audio Port to inject commands, potentially leading to arbitrary code execution.
date: "2026-04-13T22:16:28Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - command-injection
  - unifi
  - cve-2026-22563
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-22563
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22563
  - https://community.ui.com/releases/Security-Advisory-Bulletin-063/e468dd4b-5090-4ef8-89d8-939903c08e83
iocs:
  - type: url
    value: https://community.ui.com/releases/Security-Advisory-Bulletin-063/e468dd4b-5090-4ef8-89d8-939903c08e83
ioc_counts:
  url: 1
rules:
  - title: Detect Command Injection Attempt via URI
    description: Detects potential command injection attempts in HTTP requests based on suspicious URI patterns.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Command Injection via POST Request Body
    description: Detects potential command injection attempts in HTTP POST request bodies based on suspicious patterns.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-22563 describes a critical command injection vulnerability affecting UniFi Play PowerAmp (version 1.0.35 and earlier) and UniFi Play Audio Port (version 1.0.24 and earlier). The vulnerability stems from improper input validation, which allows an attacker with access to the UniFi Play network to inject arbitrary commands. Successful exploitation could lead to unauthorized access, system compromise, and potentially full control of the affected devices. This vulnerability was reported to HackerOne and assigned a CVSS v3.1 score of 9.8, indicating its severity. It is crucial for organizations using these UniFi Play devices to apply the recommended updates to mitigate this risk.

## Attack Chain

1.  Attacker gains access to the UniFi Play network (e.g., through compromised credentials or network vulnerabilities).
2.  Attacker identifies a vulnerable UniFi Play PowerAmp or Audio Port device running an affected software version (1.0.35 or earlier for PowerAmp, 1.0.24 or earlier for Audio Port).
3.  Attacker crafts a malicious payload containing an injected command.
4.  Attacker sends the malicious payload to the vulnerable device through a network request, exploiting the improper input validation vulnerability (CVE-2026-22563).
5.  The vulnerable device fails to properly sanitize the input, allowing the injected command to be executed by the underlying operating system.
6.  The injected command executes with the privileges of the UniFi Play application, potentially allowing the attacker to perform actions such as reading sensitive data, modifying system configurations, or installing malicious software.
7.  Attacker establishes a reverse shell to maintain persistent access to the compromised device.
8.  Attacker pivots to other devices in the network.

## Impact

Successful exploitation of CVE-2026-22563 can lead to full system compromise of UniFi Play PowerAmp and Audio Port devices. An attacker could gain unauthorized access to sensitive data, disrupt audio services, or use the compromised devices as a foothold to pivot to other systems on the network. Given the high CVSS score of 9.8, the impact is considered critical. The specific number of affected devices and sectors remains unknown, but organizations utilizing UniFi Play devices are at risk.

## Recommendation

*   Immediately update UniFi Play PowerAmp to version 1.0.38 or later and UniFi Play Audio Port to version 1.1.9 or later to patch CVE-2026-22563.
*   Monitor network traffic for suspicious activity originating from UniFi Play devices.
*   Implement network segmentation to limit the potential impact of a compromised device.
*   Review and enforce strong password policies to prevent unauthorized network access.
*   Deploy the Sigma rule for command injection attempts targeting UniFi Play devices (see below) to detect exploitation attempts in your environment.
