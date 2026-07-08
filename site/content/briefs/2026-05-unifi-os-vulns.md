---
title: Multiple Critical Vulnerabilities in Ubiquiti UniFi OS
slug: 2026-05-unifi-os-vulns
description: Ubiquiti has addressed multiple critical vulnerabilities including CVE-2026-34908, CVE-2026-34909, CVE-2026-34910, and CVE-2026-33000 in UniFi OS, which could allow remote attackers to make unauthorized system changes, access sensitive files, disclose information, or execute arbitrary commands on vulnerable systems.
date: "2026-05-26T20:42:17Z"
lastmod: "2026-07-08T14:51:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ui:unifi_os_server:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_cloud_gateway_industrial_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_dream_machine_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_dream_machine_pro_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_dream_machine_special_edition_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_dream_machine_pro_max_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:enterprise_fortress_gateway_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_dream_wall_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_dream_router_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_dream_router_7_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_express_7_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_network_video_recorder_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_network_video_recorder_pro_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_network_video_recorder_instant_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:enterprise_network_video_recorder_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_cloud_gateway_ultra_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_cloud_gateway_max_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_cloud_gateway_fiber_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:unifi_dream_router_5g_max_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ui:enterprise_network_video_recorder_core_firmware:*:*:*:*:*:*:*:*
has_poc: true
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
  - UniFi OS Server (< 5.0.8)
  - UniFi Connect Application < 3.4.20
  - UniFi Talk Application < 5.2.2
  - UniFi Access Application < 4.2.29
  - UniFi Protect Application < 7.1.83
  - UniFi OS < 5.1.19
affected_os:
  - Linux
  - UniFi OS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34908
    cvss: 10
    epss: 0.02452
  - id: CVE-2026-34909
    cvss: 10
    epss: 0.02269
  - id: CVE-2026-34910
    cvss: 10
    epss: 0.78555
  - id: CVE-2026-50748
    cvss: 9.9
    epss: 0.00789
  - id: CVE-2026-54400
    cvss: 9.1
    epss: 0.00257
references:
  - https://ccb.belgium.be/advisories/warning-ubiquiti-has-addressed-multiple-critical-vulnerabilities-unifi-os-patch
  - https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34908
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34909
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34910
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33000
  - https://www.securityweek.com/critical-ubiquiti-vulnerabilities-in-attackers-crosshairs/
  - https://thehackernews.com/2026/07/ubiquiti-patches-critical-unifi-flaws.html
iocs:
  - type: username
    value: John Sim
ioc_counts:
  username: 1
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
updates:
  - at: "2026-06-24T12:34:25Z"
    level: L1
    summary: OS linux
    sources:
      - securityweek
  - at: "2026-07-08T14:51:37Z"
    level: L2
    summary: poc_available; added CVE-2026-34909 +2; OS unifi os
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/ubiquiti-patches-critical-unifi-flaws.html
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
