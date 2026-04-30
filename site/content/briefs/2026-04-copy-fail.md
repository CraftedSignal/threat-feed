---
title: Linux Kernel 'Copy Fail' Local Privilege Escalation Vulnerability
slug: 2026-04-copy-fail
description: A local privilege escalation vulnerability, dubbed 'Copy Fail' (CVE-2026-31431), affects Linux kernels built since 2017, potentially allowing unprivileged users to gain root privileges.
date: "2026-04-30T09:26:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - linux
  - vulnerability
products:
  - Linux Kernel
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-31431
    cvss: 7.8
    epss: 8e-05
references:
  - https://cert.europa.eu/publications/security-advisories/2026-005/
rules:
  - title: Detect Copy Fail Exploit Execution via Syscalls
    description: Detects potential exploitation attempts of the 'Copy Fail' vulnerability by monitoring for specific syscall patterns indicative of memory manipulation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - syscall
      - linux
  - title: Detect suspicious /tmp file execution
    description: Detects execution of files from /tmp directory, which is common for exploits
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A high-severity local privilege escalation vulnerability, identified as CVE-2026-31431 and nicknamed "Copy Fail," has been discovered in the Linux kernel. This vulnerability impacts all mainstream Linux distributions that utilize a kernel built since 2017. The vulnerability allows unprivileged users to escalate their privileges to root. A public proof-of-concept (PoC) exploit is available, increasing the risk of exploitation. As of April 29, 2026, no distributions have released patched kernel packages. A fix was committed to the mainline kernel on April 1, 2026, but vendor updates are still pending across major distributions. CERT-EU recommends immediate application of interim mitigations, prioritizing Kubernetes nodes and CI/CD runners exposed to untrusted workloads.

## Attack Chain

1.  An attacker gains initial access to a Linux system through some other means (e.g., compromised service, phishing, or physical access).
2.  The attacker compiles the publicly available "Copy Fail" exploit code on the target system.
3.  The attacker executes the compiled exploit binary.
4.  The exploit leverages the vulnerability in the kernel's memory management routines related to copy operations.
5.  The vulnerability allows the attacker to overwrite kernel memory with attacker-controlled values.
6.  The attacker overwrites security-sensitive kernel data structures, such as user ID (UID) or group ID (GID) fields.
7.  The exploit modifies the attacker's effective user ID to 0 (root).
8.  The attacker now has root privileges and can execute arbitrary commands with elevated permissions.

## Impact

Successful exploitation of CVE-2026-31431 allows an unprivileged local attacker to gain full root privileges on the affected system. This can lead to complete system compromise, data theft, malware installation, and denial of service. Given the widespread use of Linux in servers, cloud infrastructure, and embedded systems, the potential impact is significant. Kubernetes nodes and CI/CD runners exposed to untrusted workloads are at particularly high risk.

## Recommendation

*   Apply the interim mitigation recommended by CERT-EU immediately, prioritizing Kubernetes nodes and CI/CD runners, as mentioned in the overview.
*   Deploy the Sigma rule "Detect Copy Fail Exploit Execution via Syscalls" to detect potential exploit attempts by monitoring specific syscall patterns associated with the vulnerability.
*   Update Linux kernel packages to the latest versions as soon as vendor-supplied patches for CVE-2026-31431 become available.
