---
title: Three Chained Zero-Days in Siemens ROX II OT Switches Lead to Root Access
slug: 2026-07-siemens-rox-ii-zero-days
description: Unit 42 and Siemens collaborated to disclose three critical chained zero-day vulnerabilities (CVE-2025-40948, CVE-2025-40947, CVE-2025-40949) in Siemens ROX II operational technology switches, allowing an attacker to achieve arbitrary file disclosure, privilege escalation to root, and persistent root-level code execution.
date: "2026-07-17T10:06:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:o:siemens:ruggedcom_rox_mx5000_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_rox_mx5000re_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_rox_rx1400_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_rox_rx1500_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_rox_rx1501_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_rox_rx1510_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_rox_rx1511_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_rox_rx1512_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_rox_rx1524_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_rox_rx1536_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_rox_rx5000_firmware:*:*:*:*:*:*:*:*
tags:
  - industrial-control-systems
  - ot-security
  - zero-day
  - privilege-escalation
  - command-injection
  - persistence
  - siemens
  - vulnerability-exploit
vendors:
  - Siemens
products:
  - ROX II OT switches
affected_os:
  - ROX II OS
  - Linux
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: An attacker leverages an insecure configuration of the xz utility, which executes with root privileges, to read any file on the switch’s file system. This vulnerability enables initial reconnaissance that could reveal critical information such as sensitive configuration files, password hashes and private cryptographic keys.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'Privilege escalation via command injection (CVE-2025-40947): This critical flaw resides in the feature key validation function. The function fails to sanitize an attacker-controlled payload before inserting it directly into a command executed with root privileges. Exploiting this allows for direct command injection and full root access.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: 'Persistent root code execution (CVE-2025-40949): Following privilege escalation, the final vulnerability is exploited in the switch’s web management task scheduler. Improper input sanitization allows an authenticated attacker to inject malicious commands into the system’s root cron table. This establishes persistent code execution, surviving system reboots and maintaining full control.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The function fails to sanitize an attacker-controlled payload before inserting it directly into a command executed with root privileges. Exploiting this allows for direct command injection and full root access.
    confidence_band: high
cves:
  - id: CVE-2025-40948
    cvss: 6.8
    epss: 0.00286
  - id: CVE-2025-40947
    cvss: 7.5
    epss: 0.00442
  - id: CVE-2025-40949
    cvss: 9.1
    epss: 0.00543
references:
  - https://unit42.paloaltonetworks.com/siemens-rox-ii-zero-day-vulnerabilities/
  - SSA-973901
  - SSA-078743
  - SSA-081142
rules:
  - title: Detects CVE-2025-40948 Exploitation - Arbitrary File Disclosure via xz
    description: Detects exploitation of CVE-2025-40948 where an attacker misuses the xz utility with specific flags (-f -c -d) to read arbitrary files on the system, indicating arbitrary file disclosure on Siemens ROX II OT switches.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1552.001
      - T1592
      - T1592.004
    data_sources:
      - process_creation
      - linux
  - title: Detects CVE-2025-40947 Exploitation - gpgv Command Injection
    description: Detects exploitation of CVE-2025-40947, a privilege escalation vulnerability where an attacker injects commands into the gpgv utility's execution via crafted feature key signatures on Siemens ROX II OT switches, indicated by shell metacharacters in the gpgv command line.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1059
      - T1059.004
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detects CVE-2025-40949 Exploitation - Cron Table Persistence
    description: Detects exploitation of CVE-2025-40949, where an authenticated attacker injects malicious commands into the system's root cron table for persistent code execution on Siemens ROX II OT switches. This rule monitors for direct modifications to system-wide crontab files or suspicious `crontab` utility usage.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053
      - T1053.003
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

A critical chain of three zero-day vulnerabilities (CVE-2025-40948, CVE-2025-40947, and CVE-2025-40949) has been discovered and detailed by Unit 42 in partnership with Siemens, affecting Siemens ROX II operational technology (OT) switches. Successful exploitation of this chain grants an attacker full privilege escalation and persistent root access on these devices, which are integral components of industrial control networks. The vulnerabilities range from Medium to Critical severity, with CVSS 3.1 scores of 6.8, 7.5, and 9.1 respectively. The attack vector progresses through arbitrary file disclosure via insecure `xz` utility configuration, privilege escalation through command injection in the feature key validation function, and persistent root code execution by injecting malicious commands into the web management task scheduler's cron table. Siemens has released advisories SSA-973901, SSA-078743, and SSA-081142, recommending customers update affected ROX II devices to firmware version V2.17.1.

## Attack Chain

1. An attacker gains network access to the Siemens ROX II device, typically via its management interface.
2. The attacker exploits CVE-2025-40948, an arbitrary file disclosure vulnerability, by leveraging an insecure configuration of a root-privileged daemon executing the `xz` utility. By providing specific parameters (`-f -c -d`) and an arbitrary file path, the attacker can read any file on the switch's file system, including sensitive configuration files, password hashes, and private cryptographic keys.
3. The attacker analyzes the disclosed information to craft a malicious payload and identify writable directories for subsequent steps.
4. The attacker uses the web UI's normal file upload functionality for feature keys to upload a crafted feature key file containing a malicious script (e.g., a Python reverse shell) to a writable directory on the switch.
5. The attacker exploits CVE-2025-40947, a command injection vulnerability, by triggering the feature key validation function. This function fails to sanitize an attacker-controlled payload within the feature key's signature field, which is then inserted directly into a command executed with root privileges via the `gpgv` utility, granting the attacker full root access.
6. With root privileges, the attacker exploits CVE-2025-40949 by using the switch’s web management task scheduler to inject malicious commands directly into the system's root cron table.
7. The injected commands establish persistent code execution, allowing the attacker to maintain full control of the device even after reboots.
8. The attacker can now perform sustained malicious activities, such as data exfiltration from the industrial network or denial-of-service attacks against critical OT infrastructure.

## Impact

The successful exploitation of these chained vulnerabilities transforms Siemens ROX II OT switches, critical components of industrial control networks, into compromised platforms. This provides attackers with persistent root access, undermining the integrity and availability of the industrial network. Such a compromise can lead to severe operational disruptions, unauthorized access to sensitive industrial processes, data exfiltration, and the potential for denial-of-service attacks. The persistence mechanism ensures that malicious activity can continue undetected across system reboots, making remediation challenging and significantly increasing the overall risk to critical infrastructure. While no specific victim counts are given, the nature of OT switches means any targeted sector utilizing these devices (e.g., manufacturing, energy, utilities) would be at risk.

## Recommendation

* Patch CVE-2025-40948, CVE-2025-40947, and CVE-2025-40949 by updating affected Siemens ROX II devices to firmware version V2.17.1 immediately, as recommended in Siemens advisories SSA-973901, SSA-078743, and SSA-081142.
* Deploy the Sigma rules in this brief to your SIEM and tune them for your Linux-based OT environments, focusing on `process_creation` and `file_event` logs.
* Monitor process creation logs for unusual invocations of `xz` with `-f -c -d` parameters, indicative of CVE-2025-40948 exploitation.
* Monitor process creation logs for `gpgv` executions containing shell metacharacters or unexpected command line arguments, potentially indicating CVE-2025-40947 exploitation.
* Monitor file integrity and modification logs for changes to `/etc/crontab` or user-specific cron files on Linux systems, which could signal CVE-2025-40949 exploitation.
