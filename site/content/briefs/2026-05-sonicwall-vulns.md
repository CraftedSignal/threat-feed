---
title: Multiple Vulnerabilities in SonicWall Firewalls Allow Remote Code Execution and Privilege Escalation
slug: 2026-05-sonicwall-vulns
description: Multiple vulnerabilities have been disclosed in SonicWall Gen6 and Gen7 firewalls, SonicOS, and NSv that can be exploited for authentication bypass, remote code execution, and privilege escalation, specifically CVE-2024-40762, CVE-2024-53704, CVE-2024-53705, and CVE-2024-53706; a proof of concept exploit is available for CVE-2024-53704, which, if exploited, can lead to internal network access and further attacks, including ransomware deployment.
date: "2026-05-19T16:11:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sonicos:7.1.2-7019:*:*:*:*:*:*:*
  - cpe:2.3:o:sonicwall:sonicos:8.0.0-8035:*:*:*:*:*:*:*
tags:
  - sonicwall
  - firewall
  - rce
  - authentication-bypass
  - privilege-escalation
vendors:
  - SonicWall
products:
  - Gen6 Hardware Firewalls
  - Gen7 Firewalls
  - Gen7 NSv
  - TZ80
  - Gen7 SonicOS Cloud NSv AWS
  - Gen7 SonicOS Cloud NSv Azure
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2024-40762
    cvss: 9.8
    epss: 0.00042
  - id: CVE-2024-53704
    cvss: 9.8
    epss: 0.93864
  - id: CVE-2024-53705
    cvss: 7.5
    epss: 0.00143
  - id: CVE-2024-53706
    cvss: 7.8
    epss: 0.00469
references:
  - https://ccb.belgium.be/advisories/warning-multiple-vulnerabilities-sonicwall-patch-immediately
  - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0003
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
rules:
  - title: Detect Suspicious SSLVPN Authentication Bypass Attempts
    description: Detects potential authentication bypass attempts in SonicWall SSLVPN, possibly indicating exploitation of CVE-2024-53704 or CVE-2024-40762.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1550.004
    data_sources:
      - network_connection
      - sonicwall
rules_count: 1
---

SonicWall has disclosed several vulnerabilities affecting their Gen6 and Gen7 hardware firewalls, NSv, TZ80, and SonicOS. These vulnerabilities, including CVE-2024-40762, CVE-2024-53704, CVE-2024-53705, and CVE-2024-53706, range from authentication bypass to remote code execution and privilege escalation. SonicWall devices are often deployed as perimeter security solutions, making them attractive targets for threat actors seeking initial access to internal networks. Reports indicate that ransomware groups, such as Akira and Fog, are actively exploiting previous SonicWall vulnerabilities. A proof-of-concept exploit has been published for CVE-2024-53704 as of February 10, 2025, increasing the likelihood of exploitation. CISA added CVE-2024-53704 to their Known Exploited Vulnerabilities Catalog on February 18, 2025.

## Attack Chain

1.  The attacker identifies a vulnerable SonicWall device exposed to the internet.
2.  The attacker exploits CVE-2024-53704, an improper authentication flaw in the SSLVPN mechanism, to bypass authentication.
3.  Alternatively, the attacker exploits CVE-2024-40762, predicting SSLVPN tokens to bypass authentication.
4.  If SSH management interface is accessible, attacker exploits CVE-2024-53705, an SSRF vulnerability, to create TCP connections to internal IP addresses and ports.
5.  If the device is a Gen7 SonicOS Cloud NSv (AWS/Azure edition), an attacker who has already compromised a low-privileged account escalates to root privileges using CVE-2024-53706.
6.  The attacker uses the gained access to move laterally within the network.
7.  The attacker deploys ransomware or exfiltrates sensitive data.

## Impact

Exploitation of these vulnerabilities allows attackers to gain unauthorized access to internal networks. With access to internal networks, attackers can conduct follow-on attacks, including ransomware deployment, data exfiltration, or other malicious activities. The vulnerabilities collectively pose a high impact on confidentiality, integrity, and availability. Ransomware groups like Akira and Fog have historically targeted SonicWall devices.

## Recommendation

*   Apply the patches provided by SonicWall immediately to address CVE-2024-40762, CVE-2024-53704, CVE-2024-53705, and CVE-2024-53706 on all affected Gen6 and Gen7 firewalls, NSv, and TZ80 appliances.
*   Monitor network traffic for suspicious connections originating from SonicWall appliances, especially connections to internal resources, to detect potential exploitation of CVE-2024-53705 as mentioned in the overview.
*   Implement the provided Sigma rule to detect suspicious SSLVPN authentication bypass attempts, which may indicate exploitation of CVE-2024-53704 or CVE-2024-40762.
