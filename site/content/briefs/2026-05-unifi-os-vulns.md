---
title: Multiple Critical Vulnerabilities in Ubiquiti UniFi OS
slug: 2026-05-unifi-os-vulns
description: Ubiquiti has addressed multiple critical vulnerabilities including CVE-2026-34908, CVE-2026-34909, CVE-2026-34910, and CVE-2026-33000 in UniFi OS, which could allow remote attackers to make unauthorized system changes, access sensitive files, disclose information, or execute arbitrary commands on vulnerable systems.
date: "2026-05-26T20:42:17Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - unifi
  - command_injection
  - path_traversal
  - improper_access_control
vendors:
  - Ubiquiti
products:
  - UniFi OS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34908
    cvss: 10
    epss: 0.00015
  - id: CVE-2026-34909
    cvss: 10
    epss: 0.0002
  - id: CVE-2026-34910
    cvss: 10
    epss: 0.00083
  - id: CVE-2026-33000
    cvss: 9.1
    epss: 0.0005
references:
  - https://ccb.belgium.be/advisories/warning-ubiquiti-has-addressed-multiple-critical-vulnerabilities-unifi-os-patch
  - https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34908
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34909
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34910
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33000
rules:
  - title: Detect UniFi OS Path Traversal Attempt
    description: Detects CVE-2026-34909 exploitation — Path Traversal vulnerability attempt in UniFi OS via web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect UniFi OS Command Injection Attempt
    description: Detects CVE-2026-34910 and CVE-2026-33000 exploitation — Command Injection vulnerability attempt in UniFi OS via web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Ubiquiti has released security updates to address multiple critical vulnerabilities in UniFi OS, a system designed for managing IT infrastructure including networking, security, and other services. These vulnerabilities, disclosed in May 2026, affect a wide range of UniFi OS products. Exploitation of these vulnerabilities could allow remote attackers to make unauthorized system changes, access sensitive files, disclose information, or execute arbitrary commands on vulnerable systems. Given the central role of UniFi OS devices in managing networks, successful exploitation could lead to significant compromise, including lateral movement to other systems. The affected products include UCG-Industrial, UDM, UDM-Pro, UDM-SE, UDM-Pro-Max, EFG, UDW, UDR, UDR7, Express 7, UNVR, UNVR-Pro, UNVR-Instant, ENVR, UCG-Ultra, UCG-Max, UCG-Fiber, UDR-5G, ENVR-Core, UCKP, UCK, UCK-Enterprise, UniFi OS Server, UNVR-G2, UNVR-G2-Pro, UDM-Beast, UNAS-2, UNAS-4, UNAS-Pro, UNAS-Pro-4, UNAS-Pro-8, and Express.

## Attack Chain

1.  Attacker identifies a vulnerable UniFi OS device accessible on the network (e.g., CVE-2026-34908, CVE-2026-34909, CVE-2026-34910).
2.  The attacker exploits an Improper Access Control vulnerability (CVE-2026-34908) to bypass authentication or authorization mechanisms.
3.  Alternatively, the attacker leverages a Path Traversal vulnerability (CVE-2026-34909) to read sensitive files on the file system.
4.  The attacker uses the Path Traversal vulnerability to access files containing credentials or configuration data to further compromise the system.
5.  Or, the attacker exploits an Improper Input Validation vulnerability (CVE-2026-34910 or CVE-2026-33000) to inject arbitrary commands into the system.
6.  The attacker executes commands to gain a shell on the UniFi OS device.
7.  The attacker establishes persistence on the compromised UniFi OS device.
8.  The attacker uses the compromised device as a pivot point to move laterally within the network and compromise other systems.

## Impact

Successful exploitation of these vulnerabilities can lead to full compromise of UniFi OS devices. Since these devices are often used to manage critical network infrastructure, a successful attack could allow an attacker to gain control of the entire network, leading to data theft, service disruption, and other malicious activities. The CCB has assessed these vulnerabilities as critical, given the high CVSS scores and the potential impact on confidentiality, integrity, and availability of targeted devices.

## Recommendation

*   Immediately patch Ubiquiti UniFi OS devices to the latest version to address CVE-2026-34908, CVE-2026-34909, CVE-2026-34910, and CVE-2026-33000.
*   Enable network monitoring to detect suspicious activity related to exploitation attempts, ensuring a swift response in case of an intrusion.
*   Implement the Sigma rule "Detect UniFi OS Path Traversal Attempt" to identify potential exploitation of CVE-2026-34909 via web server logs.
*   Deploy the Sigma rule "Detect UniFi OS Command Injection Attempt" to identify potential exploitation of CVE-2026-34910 and CVE-2026-33000 via web server logs.
