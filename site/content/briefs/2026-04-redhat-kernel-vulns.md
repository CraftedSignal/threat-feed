---
title: Multiple Vulnerabilities in Red Hat Linux Kernel
slug: 2026-04-redhat-kernel-vulns
description: Multiple vulnerabilities in the Red Hat Linux kernel allow for arbitrary code execution, privilege escalation, and remote denial of service.
date: "2026-04-30T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - kernel
  - redhat
  - execution
  - privilege-escalation
  - denial-of-service
vendors:
  - Red Hat
products:
  - Red Hat CodeReady Linux Builder
  - Red Hat Enterprise Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
cves:
  - id: CVE-2025-68741
    epss: 0.00035
  - id: CVE-2025-38024
    cvss: 7.8
    epss: 0.00086
  - id: CVE-2025-38180
    cvss: 7.8
    epss: 0.00023
  - id: CVE-2026-23111
    cvss: 7.8
    epss: 0.00018
  - id: CVE-2026-23204
    cvss: 7.1
    epss: 0.00018
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0521/
  - https://access.redhat.com/errata/RHSA-2026:10756
  - https://access.redhat.com/errata/RHSA-2026:10996
  - https://access.redhat.com/errata/RHSA-2026:11313
  - https://www.cve.org/CVERecord?id=CVE-2022-50053
  - https://www.cve.org/CVERecord?id=CVE-2023-53539
  - https://www.cve.org/CVERecord?id=CVE-2025-38024
  - https://www.cve.org/CVERecord?id=CVE-2025-38180
  - https://www.cve.org/CVERecord?id=CVE-2025-68741
  - https://www.cve.org/CVERecord?id=CVE-2025-71238
  - https://www.cve.org/CVERecord?id=CVE-2026-23001
  - https://www.cve.org/CVERecord?id=CVE-2026-23097
  - https://www.cve.org/CVERecord?id=CVE-2026-23111
  - https://www.cve.org/CVERecord?id=CVE-2026-23193
  - https://www.cve.org/CVERecord?id=CVE-2026-23204
  - https://www.cve.org/CVERecord?id=CVE-2026-23216
  - https://www.cve.org/CVERecord?id=CVE-2026-23231
  - https://www.cve.org/CVERecord?id=CVE-2026-31402
rules:
  - title: Detect Suspicious Kernel Module Loading
    description: Detects the use of `insmod` or `modprobe` commands to load kernel modules, which can be indicative of rootkit installation or exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.005
    data_sources:
      - process_creation
      - linux
  - title: Detect attempts to read kernel memory via /dev/kmem or /dev/mem
    description: Detects processes attempting to directly read kernel memory, often used in exploit attempts
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On April 30, 2026, CERT-FR published an advisory regarding multiple vulnerabilities in the Red Hat Linux kernel. These vulnerabilities, detailed in Red Hat Security Advisories RHSA-2026:10756, RHSA-2026:10996, and RHSA-2026:11313, can lead to significant security risks including arbitrary code execution, privilege escalation, and remote denial of service. The affected systems include various versions and architectures of Red Hat CodeReady Linux Builder and Red Hat Enterprise Linux. Successful exploitation of these vulnerabilities could allow attackers to gain unauthorized access, control systems, or disrupt services, impacting the confidentiality, integrity, and availability of affected systems.

## Attack Chain

1.  **Initial Compromise (via unconfirmed vector):** An attacker identifies a vulnerable Red Hat Linux system running an affected kernel version. While the exact exploit vector isn't specified in the advisory, it involves a vulnerability in the kernel.
2.  **Exploit Trigger:** The attacker triggers a specific kernel vulnerability, such as those identified as CVE-2026-23001 or CVE-2026-31402, by sending a crafted input to a vulnerable kernel component. The specific method depends on the nature of each CVE.
3.  **Code Execution:** Upon successful exploitation, the attacker achieves arbitrary code execution within the kernel context. This allows the attacker to run malicious code directly on the system.
4.  **Privilege Escalation:** Leveraging the code execution capability, the attacker exploits another vulnerability (e.g., CVE-2025-68741) to escalate privileges to root or SYSTEM. This may involve exploiting race conditions, memory corruption bugs, or other privilege escalation flaws within the kernel.
5.  **System Control:** With elevated privileges, the attacker gains full control over the compromised system. They can now access sensitive data, modify system configurations, install backdoors, or move laterally to other systems within the network.
6.  **Lateral Movement (Optional):** The attacker uses the compromised system as a launching point to attack other systems on the network, potentially exploiting other vulnerabilities or using stolen credentials.
7.  **Persistence (Optional):** The attacker establishes persistence on the compromised system to maintain access even after reboots. This may involve installing rootkits, modifying system startup scripts, or creating rogue user accounts.
8.  **Denial of Service/Data Exfiltration/etc.:** Depending on their objectives, the attacker may use the compromised system to launch denial-of-service attacks against other targets, exfiltrate sensitive data, or cause other damage.

## Impact

Successful exploitation of these kernel vulnerabilities can lead to complete system compromise, allowing attackers to execute arbitrary code, escalate privileges, and cause denial of service. The wide range of affected Red Hat Enterprise Linux and CodeReady Linux Builder versions implies a potentially large number of vulnerable systems. This can result in significant data breaches, system downtime, financial losses, and reputational damage for affected organizations.

## Recommendation

*   Apply the patches provided in Red Hat Security Advisories RHSA-2026:10756, RHSA-2026:10996, and RHSA-2026:11313 to remediate the vulnerabilities.
*   Prioritize patching systems based on their criticality and exposure to external networks.
*   Monitor systems for suspicious activity that may indicate exploitation attempts, focusing on unexpected kernel module loads or privilege escalations using process_creation logging.
*   Deploy the Sigma rule detecting suspicious kernel module loading to identify potential rootkit installation attempts.
*   Investigate any alerts generated by the deployed Sigma rules to determine the scope and impact of potential compromises.
