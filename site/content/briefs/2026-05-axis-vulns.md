---
title: Multiple Vulnerabilities in Axis Products Allow Remote Code Execution and Privilege Escalation
slug: 2026-05-axis-vulns
description: Multiple vulnerabilities in Axis products allow remote arbitrary code execution and privilege escalation in Axis OS versions 12.10.x prior to 12.10.37 and 12.9.x prior to 12.9.33 for Active Track.
date: "2026-05-12T14:11:24Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - vulnerability
  - rce
  - privilege-escalation
vendors:
  - Axis
products:
  - Axis OS Active Track
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-0541
    cvss: 6.7
  - id: CVE-2026-0802
    cvss: 6
  - id: CVE-2026-0804
    cvss: 6.7
  - id: CVE-2026-1185
    cvss: 5.4
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0568/
  - https://www.axis.com/dam/public/fa/50/c7/cve-2026-0541pdf-en-US-530730.pdf
  - https://www.axis.com/dam/public/67/b8/75/cve-2026-0802pdf-en-US-530731.pdf
  - https://www.axis.com/dam/public/51/64/ea/cve-2026-0804pdf-en-US-530732.pdf
  - https://www.axis.com/dam/public/69/df/8d/cve-2026-1185pdf-en-US-530733.pdf
  - https://www.cve.org/CVERecord?id=CVE-2026-0541
  - https://www.cve.org/CVERecord?id=CVE-2026-0802
  - https://www.cve.org/CVERecord?id=CVE-2026-0804
  - https://www.cve.org/CVERecord?id=CVE-2026-1185
rules:
  - title: Detect Suspicious Axis Network Activity
    description: Detects potential exploitation attempts against Axis devices via unusual network connections.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2026-XXXX Exploitation — Suspicious Process Execution from Network Traffic
    description: Detects potential exploitation attempts targeting Axis devices by monitoring process creation events initiated from network services. Replace CVE-2026-XXXX with the specific CVE ID.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Multiple vulnerabilities have been discovered in Axis products that could allow an attacker to perform remote code execution (RCE) and escalate privileges. The affected software is Axis OS versions 12.10.x prior to 12.10.37 and 12.9.x prior to 12.9.33 when running Active Track. These vulnerabilities, identified as CVE-2026-0541, CVE-2026-0802, CVE-2026-0804, and CVE-2026-1185, pose a significant risk to systems running the affected versions. Successful exploitation could allow an attacker to gain complete control over the affected device. Defenders should apply patches as soon as possible.

## Attack Chain

1.  The attacker identifies a vulnerable Axis device running a susceptible version of Axis OS with Active Track enabled.
2.  The attacker sends a crafted network request to the device, targeting one of the exploitable vulnerabilities (CVE-2026-0541, CVE-2026-0802, CVE-2026-0804, or CVE-2026-1185).
3.  The vulnerable software improperly handles the request, leading to memory corruption or other exploitable conditions.
4.  The attacker injects malicious code into the device's memory.
5.  The attacker gains arbitrary code execution on the device.
6.  The attacker escalates privileges to gain administrative or root access.
7.  The attacker uses the elevated privileges to install malware, modify configurations, or steal sensitive data.
8.  The attacker uses the compromised device as a pivot point to attack other devices on the network, or maintains persistence for future access.

## Impact

Successful exploitation of these vulnerabilities allows attackers to achieve remote code execution and privilege escalation on affected Axis devices. This could lead to a complete compromise of the device, allowing attackers to steal sensitive data, install malware, or use the device as a foothold to attack other systems on the network. The number of potential victims depends on the number of deployed devices running the vulnerable versions of Axis OS with Active Track.

## Recommendation

*   Apply the security patches provided by Axis to address CVE-2026-0541, CVE-2026-0802, CVE-2026-0804, and CVE-2026-1185 on all affected Axis OS Active Track devices (see References).
*   Monitor network traffic for suspicious activity targeting Axis devices, such as unexpected requests to exposed services using a network intrusion detection system.
*   Deploy the Sigma rule "Detect Suspicious Axis Network Activity" to identify potential exploitation attempts in network connection logs.
*   Upgrade Axis OS to a version that is not affected by these vulnerabilities to prevent exploitation.
