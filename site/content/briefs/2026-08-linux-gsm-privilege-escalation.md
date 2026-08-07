---
title: Exploitation of Linux Kernel GSM 0710 TTY Multiplexor Race Condition
slug: 2026-08-linux-gsm-privilege-escalation
description: An unprivileged local user can escalate privileges to root by exploiting a race condition in the Linux kernel GSM 0710 tty multiplexor (CVE-2023-6546).
date: "2026-08-07T15:16:03Z"
lastmod: "2026-08-07T15:16:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.5:rc1:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.5:rc2:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.5:rc3:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.5:rc4:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.5:rc5:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.5:rc6:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
  - kernel
vendors:
  - Linux
products:
  - Linux kernel
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The following analytic detects the commands used in a race condition found in the GSM 0710 tty multiplexor in the Linux kernel.
    confidence_band: high
cves:
  - id: CVE-2023-6546
    cvss: 7
    epss: 0.00767
references:
  - https://access.redhat.com/security/cve/cve-2023-6546
  - https://github.com/Nassim-Asrir/ZDI-24-020/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/linux_possible_system_binary_backdoor.yml
rules:
  - title: Detect CVE-2023-6546 Exploitation - Suspicious GSM Module Manipulation
    description: Detects command sequences involving the unloading of the n_gsm kernel module followed by shell execution, indicative of CVE-2023-6546 exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to identify potential exploitation attempts
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic methodology for detection
  mitigation_plan:
    - priority: short_term
      action: Restrict unprivileged user access to modprobe and rmmod binaries
      owner: IT Operations
      addresses: CVE-2023-6546
      evidence: Uncontrolled access to module commands facilitates the exploit chain
updates:
  - at: "2026-08-07T15:16:26Z"
    level: L1
    summary: OS linux
    sources:
      - splunk-escu
    source_urls:
      - https://github.com/splunk/security_content/blob/main/detections/endpoint/linux_possible_system_binary_backdoor.yml
---

This threat involves a local privilege escalation vulnerability in the Linux kernel, specifically within the GSM 0710 tty multiplexor module (n_gsm). The vulnerability, tracked as CVE-2023-6546, arises from a race condition triggered when two threads execute the GSMIOC_SETCONF ioctl on the same tty file descriptor while the gsm line discipline is active. An unprivileged local attacker can leverage this race condition to gain root privileges. Defense teams should monitor for anomalous kernel module management and shell execution patterns that coincide with the loading or unloading of the n_gsm kernel module.

## Attack Chain

1. Attacker gains initial access to the Linux system as an unprivileged user.
2. Attacker prepares a local exploit payload targeting the GSM 0710 tty multiplexor.
3. Attacker initiates multiple threads attempting to trigger the race condition using the GSMIOC_SETCONF ioctl.
4. Attacker forces the unloading of the `n_gsm` kernel module using `rmmod` to manipulate the module state.
5. Attacker executes shell commands (e.g., `/bin/bash` or `/bin/sh`) following the successful race condition exploitation.
6. Attacker confirms privilege escalation to root.

## Impact

Successful exploitation results in full local privilege escalation, allowing an unprivileged attacker to obtain root-level access on the affected system. This compromise permits the attacker to bypass access controls, install persistence mechanisms, exfiltrate sensitive data, or deploy further malicious payloads.

## Recommendation

Deploy the provided Sigma rule to detect suspicious process activity associated with GSM module manipulation. Ensure that kernel auditing and Sysmon for Linux are configured to log process creation events. Restrict the ability of unprivileged users to load or unload kernel modules using `rmmod`.
