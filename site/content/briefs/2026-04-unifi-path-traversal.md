---
title: UniFi Play Path Traversal Vulnerability (CVE-2026-22562)
slug: 2026-04-unifi-path-traversal
description: A path traversal vulnerability in UniFi Play devices allows an attacker with network access to write arbitrary files, leading to remote code execution.
date: "2026-04-14T14:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - rce
  - unifi
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-22562
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22562
  - https://community.ui.com/releases/Security-Advisory-Bulletin-063/e468dd4b-5090-4ef8-89d8-939903c08e83
rules:
  - title: Path Traversal in URI
    description: Detects path traversal attempts in HTTP requests
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Suspicious File Creation in Common Web Directories
    description: Detects creation of executable files in web server directories which could be a sign of web shell deployment after a path traversal
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-22562 describes a critical path traversal vulnerability affecting UniFi Play PowerAmp (version 1.0.35 and earlier) and UniFi Play Audio Port (version 1.0.24 and earlier) devices. An attacker with access to the UniFi Play network can exploit this vulnerability to write arbitrary files on the file system. This capability can then be leveraged to achieve remote code execution (RCE) on the vulnerable device. Successful exploitation requires network access to the affected UniFi Play devices, making internal networks the primary target. The vulnerability was disclosed in April 2026. Defenders should prioritize patching vulnerable devices to prevent potential compromise.

## Attack Chain

1.  Attacker gains access to the UniFi Play network (e.g., via compromised credentials or network intrusion).
2.  Attacker identifies a vulnerable UniFi Play device (PowerAmp <= 1.0.35 or Audio Port <= 1.0.24).
3.  Attacker crafts a malicious HTTP request containing a path traversal sequence (e.g., "../../../") in a file upload or download parameter.
4.  The vulnerable device processes the request without proper sanitization, allowing the attacker to write a file to an arbitrary location on the file system.
5.  Attacker writes a malicious script (e.g., a shell script or executable) to a location where it can be executed (e.g., a startup directory or cron job).
6.  Attacker triggers the execution of the malicious script (e.g., by rebooting the device or waiting for the cron job to run).
7.  The malicious script executes with the privileges of the UniFi Play device, granting the attacker remote code execution.
8.  Attacker uses RCE to further compromise the device, pivot to other network assets, or establish persistence.

## Impact

Successful exploitation of CVE-2026-22562 allows an attacker to gain complete control of the vulnerable UniFi Play device. This can lead to data exfiltration, device disruption, and further compromise of the network to which the device is connected. Given the potential for RCE, an attacker could potentially use compromised devices as entry points to other systems on the network, thus expanding their reach and increasing the overall impact of the attack. Organizations using affected UniFi Play devices are at high risk.

## Recommendation

*   Immediately update UniFi Play PowerAmp to version 1.0.38 or later and UniFi Play Audio Port to version 1.1.9 or later to patch CVE-2026-22562 (see Overview).
*   Monitor network traffic for suspicious HTTP requests containing path traversal sequences targeting UniFi Play devices using the provided Sigma rule (Path Traversal in URI).
*   Implement network segmentation to limit the impact of a potential compromise of a UniFi Play device.
*   Review and harden access controls to the UniFi Play network to prevent unauthorized access by potential attackers.
