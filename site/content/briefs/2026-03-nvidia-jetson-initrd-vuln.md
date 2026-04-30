---
title: NVIDIA Jetson Linux initrd Command Injection Vulnerability (CVE-2026-24154)
slug: 2026-03-nvidia-jetson-initrd-vuln
description: CVE-2026-24154 is a vulnerability in NVIDIA Jetson Linux where an unprivileged attacker with physical access can inject incorrect command line arguments into initrd, potentially leading to code execution, privilege escalation, denial of service, data tampering, and information disclosure.
date: "2026-03-31T17:16:30Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-24154
  - nvidia
  - jetson
  - initrd
  - command injection
  - privilege escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-24154
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24154
  - https://nvidia.custhelp.com/app/answers/detail/a_id/5797
  - https://www.cve.org/CVERecord?id=CVE-2026-24154
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Modified Kernel Command Line
    description: Detects modifications to the kernel command line, potentially indicating an attempt to inject malicious arguments during the boot process.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Early Boot Shell Activity
    description: Detects execution of shell binaries (sh, bash, etc.) during the early boot process, which could indicate unauthorized access or command injection via initrd.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-24154 affects NVIDIA Jetson Linux and stems from a flaw within the initrd (initial RAM disk) process.  An unprivileged attacker with physical access to a vulnerable device can inject malicious command-line arguments during the boot process. This injection can subvert the intended system initialization, leading to a variety of severe consequences.  The vulnerability was published on March 31, 2026, and has a CVSS v3.1 score of 7.6. The affected versions of Jetson Linux are not specified in the source.  Successful exploitation allows attackers to execute arbitrary code, escalate privileges, cause denial of service, tamper with data, and disclose sensitive information. Defenders should focus on securing physical access and monitoring boot processes for unauthorized modifications.

## Attack Chain

1.  Attacker gains physical access to the NVIDIA Jetson device.
2.  Attacker interrupts the boot process to gain access to the bootloader. This may involve pressing specific keys during startup or utilizing hardware tools.
3.  Attacker modifies the kernel command line arguments passed to the initrd. This is achieved by manipulating bootloader settings.
4.  The modified command line arguments inject malicious commands or alter the execution path within the initrd environment.
5.  During initrd execution, the injected commands are processed, leading to code execution within the early boot environment. This bypasses normal user authentication and security measures.
6.  The attacker leverages the initial code execution to escalate privileges by exploiting vulnerabilities within the initrd environment or system binaries.
7.  With escalated privileges, the attacker gains control over the system, enabling them to install persistent backdoors, tamper with system configurations, or exfiltrate sensitive data.
8.  The final objective is achieved, which can range from complete system compromise and data theft to denial-of-service attacks.

## Impact

Successful exploitation of CVE-2026-24154 can lead to a complete compromise of the NVIDIA Jetson Linux device. The attacker can achieve code execution, escalate privileges, and gain persistent access. This could result in data breaches, system instability, and the deployment of malicious software. While the number of potential victims and specific sectors targeted are not mentioned in the source, the vulnerability affects devices used in various embedded systems, robotics, and edge computing applications.

## Recommendation

*   Restrict physical access to NVIDIA Jetson devices to prevent unauthorized manipulation of the boot process.
*   Monitor boot logs and system events for unusual command-line arguments or modifications to the initrd environment. Deploy the Sigma rule `Detect Modified Kernel Command Line` to identify suspicious boot activity.
*   Consider implementing secure boot mechanisms to prevent unauthorized modifications to the bootloader and kernel.
*   Investigate any unauthorized access attempts or physical tampering with Jetson devices.
*   Apply any available patches or updates from NVIDIA to mitigate the vulnerability when they become available via NVIDIA's customer support portal referenced in the advisory.
*   Monitor network connections originating from the device after boot for unexpected or malicious activity, using network connection logs, to identify potential exploitation attempts.
