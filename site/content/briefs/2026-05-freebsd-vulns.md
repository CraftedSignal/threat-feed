---
title: Multiple Vulnerabilities in FreeBSD
slug: 2026-05-freebsd-vulns
description: FreeBSD published security advisories addressing multiple vulnerabilities including remote code execution, local privilege escalation, heap overflow, and stack overflow, affecting all supported versions.
date: "2026-05-04T13:44:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - freebsd
  - vulnerability
  - rce
  - privilege-escalation
vendors:
  - FreeBSD
products:
  - FreeBSD
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-35547
    cvss: 8.1
    epss: 0.00059
  - id: CVE-2026-7164
    cvss: 7.5
    epss: 0.00164
  - id: CVE-2026-7270
    cvss: 7.8
    epss: 0.00015
  - id: CVE-2026-42511
    cvss: 8.1
    epss: 0.00059
references:
  - https://cyber.gc.ca/en/alerts-advisories/freebsd-security-advisory-av26-415
  - https://www.freebsd.org/security/advisories/FreeBSD-SA-26:17.libnv.asc
  - https://www.freebsd.org/security/advisories/FreeBSD-SA-26:14.pf.asc
  - https://www.freebsd.org/security/advisories/FreeBSD-SA-26:13.exec.asc
  - https://www.freebsd.org/security/advisories/FreeBSD-SA-26:12.dhclient.asc
  - https://www.freebsd.org/security/advisories/
rules:
  - title: Detect Suspicious DHCP Client Activity
    description: Detects suspicious DHCP client activity that could indicate exploitation of CVE-2026-42511
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - freebsd
  - title: Detect Execve System Call with Suspicious Arguments
    description: Detects execve() system calls with arguments indicative of privilege escalation attempts related to CVE-2026-7270
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On April 29, 2026, FreeBSD released security advisories to address multiple vulnerabilities across all supported versions of the operating system. These vulnerabilities include CVE-2026-35547, a heap overflow in libnv; CVE-2026-7164, a stack overflow in the pf packet filter when parsing crafted SCTP packets; CVE-2026-7270, a local privilege escalation vulnerability via execve(); and CVE-2026-42511, a remote code execution vulnerability exploitable through malicious DHCP options. The variety and severity of these issues pose a significant risk to FreeBSD systems, potentially enabling attackers to execute arbitrary code, escalate privileges, or cause denial-of-service conditions. Prompt patching is crucial to mitigate these risks.

## Attack Chain

1.  **Initial Access (CVE-2026-42511):** An attacker sends a malicious DHCP offer to a vulnerable FreeBSD client. The crafted DHCP options contain shellcode designed to exploit a buffer overflow in the DHCP client.
2.  **Code Execution:** The vulnerable DHCP client processes the malicious DHCP options, resulting in the execution of attacker-controlled code within the context of the dhclient process.
3.  **Privilege Escalation (CVE-2026-7270):** The attacker exploits a vulnerability in the execve() system call to escalate privileges. This involves crafting a specific executable that leverages the flaw to execute arbitrary commands with elevated permissions.
4.  **Memory Corruption (CVE-2026-35547):** The attacker triggers a heap overflow in libnv by providing a specially crafted input. This input causes the libnv library to allocate insufficient memory, leading to data corruption.
5.  **Packet Injection/Manipulation (CVE-2026-7164):** An attacker sends a crafted SCTP packet to a FreeBSD system utilizing the pf packet filter. The malformed packet triggers a stack overflow during parsing within the pf module.
6.  **Lateral Movement:** With elevated privileges, the attacker can move laterally within the network, accessing sensitive data and systems.
7.  **Data Exfiltration/System Compromise:** The attacker exfiltrates sensitive data or installs persistent backdoors, achieving complete system compromise.

## Impact

Successful exploitation of these vulnerabilities could lead to a range of severe consequences, including remote code execution, local privilege escalation, data breaches, and complete system compromise. While the exact number of affected systems is unknown, given the wide deployment of FreeBSD, a significant number of servers and workstations are potentially at risk. Sectors heavily reliant on FreeBSD, such as hosting providers and network infrastructure companies, are particularly vulnerable.

## Recommendation

*   Apply the security patches released by FreeBSD to address CVE-2026-35547, CVE-2026-7164, CVE-2026-7270, and CVE-2026-42511 immediately on all affected systems.
*   Deploy the Sigma rule "Detect Suspicious DHCP Client Activity" to identify potential exploitation attempts targeting CVE-2026-42511 via malicious DHCP options.
*   Enable process accounting and audit logging to monitor for suspicious execve() calls, as indicated by CVE-2026-7270, and create a detection rule for unusual privilege escalations.
*   Monitor network traffic for malformed SCTP packets that could trigger the stack overflow in pf (CVE-2026-7164). Implement a network-based detection rule to identify such packets.
