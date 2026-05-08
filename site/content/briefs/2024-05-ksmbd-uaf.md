---
title: CVE-2026-31718 ksmbd Use-After-Free Vulnerability
slug: 2024-05-ksmbd-uaf
description: CVE-2026-31718 is a use-after-free vulnerability in the ksmbd kernel module, specifically in the __ksmbd_close_fd() function, which can be triggered via the durable scavenger mechanism, potentially leading to arbitrary code execution.
date: "2026-05-08T07:05:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:rc1:*:*:*:*:*:*
tags:
  - use-after-free
  - smb
  - ksmbd
  - CVE-2026-31718
  - kernel
vendors:
  - Microsoft
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-31718
    cvss: 9.8
    epss: 0.00057
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-31718
rules:
  - title: Detect CVE-2026-31718 Exploitation Attempt — Durable Handle Request
    description: Detects CVE-2026-31718 exploitation attempt by monitoring for SMB requests indicative of durable handle usage, which may precede a use-after-free trigger.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2026-31718 Exploitation Attempt — SMB2 Close Request
    description: Detects CVE-2026-31718 exploitation attempt — an SMB2 close request following a durable handle request which could indicate an attempt to trigger the UAF.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On May 8, 2026, Microsoft published details for CVE-2026-31718, a use-after-free vulnerability affecting the ksmbd kernel module. The vulnerability resides in the `__ksmbd_close_fd()` function and is triggered through the durable scavenger functionality. Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code in the context of the kernel. The vulnerability affects systems utilizing the ksmbd kernel module for SMB server functionality. Due to the nature of kernel-level vulnerabilities, this poses a significant risk to the confidentiality, integrity, and availability of affected systems.

## Attack Chain

1. An attacker establishes a valid SMB connection with a vulnerable ksmbd server.
2. The attacker initiates a durable file handle request, instructing the server to maintain a persistent file handle.
3. The server creates a file object and associates it with the durable file handle.
4. The attacker triggers the durable scavenger, a routine designed to clean up stale or unused durable handles.
5. Due to a flaw in `__ksmbd_close_fd()`, the server incorrectly frees the file object while the durable file handle is still active.
6. The attacker attempts to access the file object through the previously established durable file handle.
7. This access triggers a use-after-free condition, potentially allowing the attacker to overwrite kernel memory.
8. By carefully crafting the memory overwrite, the attacker achieves arbitrary code execution within the kernel.

## Impact

Successful exploitation of CVE-2026-31718 allows an attacker to execute arbitrary code within the kernel context of the affected system. This can lead to a complete compromise of the system, allowing the attacker to gain full control, steal sensitive data, or cause a denial of service. Given the kernel-level nature of the vulnerability, there is a high risk of privilege escalation and lateral movement within the network.

## Recommendation

*   Apply the security updates released by Microsoft to patch CVE-2026-31718 to remediate the underlying use-after-free vulnerability.
*   Monitor systems running ksmbd for unusual SMB activity, specifically related to durable file handles, using network connection logs.
*   Deploy the provided Sigma rule to detect potential attempts to trigger the vulnerable `__ksmbd_close_fd()` function by monitoring for specific SMB protocol requests related to durable handles.
