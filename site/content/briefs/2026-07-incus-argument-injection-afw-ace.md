---
title: Incus Argument Injection Vulnerability Leads to Arbitrary File Write and Command Execution
slug: 2026-07-incus-argument-injection-afw-ace
description: An argument injection vulnerability (CVE-2026-48755) exists in Incus due to improper validation of the user-provided backup compression algorithm, allowing an authenticated attacker to inject arbitrary arguments into the command line, leading to an arbitrary file write on the host and subsequent arbitrary command execution.
date: "2026-07-03T10:35:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - argument-injection
  - arbitrary-file-write
  - remote-code-execution
  - container-escape
  - linux
vendors:
  - LXC
products:
  - 'Incus (vulnerable: < 7.2.0)'
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Improper validation of user-provided backup compression algorithm leads to argument injection in the constructed command line... the daemon executes the equivalent of: zstd -c -d -f --pass-through -o /etc/cron.d/incus-zstd-rce -- /var/lib/incus/.../payload'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: 'This leads to an arbitrary file write on the host, possibly leading to arbitrary command execution... With a value like: zstd -d -f --pass-through -o /etc/cron.d/incus-zstd-rce -- /var/lib/incus/.../payload'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: 'This leads to an arbitrary file write on the host, possibly leading to arbitrary command execution... With a value like: zstd -d -f --pass-through -o /etc/cron.d/incus-zstd-rce -- /var/lib/incus/.../payload'
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse of Mechanism
    evidence: arbitrary file write on the host, possibly leading to arbitrary command execution.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: leads to an arbitrary file write on the host, possibly leading to arbitrary command execution.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-v6mj-8pf4-hhw4
iocs:
  - type: file_path
    value: /etc/cron.d/incus-zstd-rce
  - type: file_path
    value: /var/lib/incus/.../payload
ioc_counts:
  file_path: 2
rules:
  - title: 'CVE-2026-48755: Incus Zstd Argument Injection Attempt'
    description: Detects CVE-2026-48755 exploitation — suspicious command line arguments passed to 'zstd' indicative of argument injection attempting arbitrary file write, likely targeting /etc/cron.d.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
    techniques:
      - T1059
      - T1546.001
    data_sources:
      - process_creation
      - linux
  - title: 'CVE-2026-48755: Incus Host Cron Job Creation'
    description: Detects CVE-2026-48755 exploitation — suspicious file creation or modification in '/etc/cron.d/' by a non-standard process, indicating a potential arbitrary file write from Incus or another service.
    platform: sigma
    severity: high
    tactics:
      - impact
      - persistence
    techniques:
      - T1491
      - T1543.002
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-48755, affects Incus versions prior to 7.2.0, stemming from an argument injection flaw in its backup compression algorithm processing. The flaw allows an authenticated attacker to manipulate the `compression_algorithm` parameter, injecting arbitrary command-line arguments into the `zstd` compressor execution. This enables an arbitrary file write (AFW) operation on the host system where Incus is running. Attackers can leverage this AFW to write malicious content to sensitive locations, such as cron job directories (`/etc/cron.d/`), thereby achieving arbitrary command execution (ACE). This vulnerability is particularly dangerous as it provides a pathway from a compromised Incus instance to full system compromise of the host. Defenders should prioritize patching and monitoring for suspicious `zstd` command executions and unexpected file writes in system configuration paths.

## Attack Chain

1.  An authenticated attacker (e.g., a user with Incus client certificate access to the API) gains control over an Incus instance.
2.  The attacker uploads a malicious payload (e.g., a reverse shell script or system command) into the compromised Incus instance, accessible from the host filesystem.
3.  The attacker crafts a malicious `compression_algorithm` string containing argument injection payloads, such as `zstd -d -f --pass-through -o /etc/cron.d/incus-zstd-rce -- /var/lib/incus/.../payload`.
4.  The attacker initiates a direct backup request to the Incus API for the compromised instance, specifying the crafted malicious `compression_algorithm`.
5.  Incus, due to improper validation, constructs and executes a command similar to `exec.Command("zstd", "-c", "-d", "-f", "--pass-through", "-o", "/etc/cron.d/incus-zstd-rce", "--", "/var/lib/incus/.../payload")`.
6.  The `zstd` command's argument injection leads to an arbitrary file write, copying the attacker-controlled payload from within the Incus instance to `/etc/cron.d/incus-zstd-rce` on the host system.
7.  The newly created cron job on the host system is executed by the cron daemon at the specified interval, resulting in arbitrary command execution on the Incus host.
8.  The executed command establishes persistence or performs further malicious actions, such as data exfiltration or deploying additional malware.

## Impact

The successful exploitation of CVE-2026-48755 leads to an arbitrary file write on the host operating system, which attackers can immediately leverage for arbitrary command execution. This allows a privileged user within an Incus instance to escalate privileges to root on the underlying host, circumventing containerization. Such a compromise grants the attacker full control over the Incus host, potentially impacting all other instances running on that server, and facilitating lateral movement within the network. This vulnerability affects Incus users running versions prior to 7.2.0, with potential for widespread compromise in environments where Incus is used for virtualization or container management.

## Recommendation

*   Patch CVE-2026-48755 by upgrading all Incus installations to version 7.2.0 or higher immediately.
*   Deploy the provided Sigma rule "CVE-2026-48755: Incus Zstd Argument Injection Attempt" to your SIEM to detect suspicious execution of `zstd` with potential argument injection patterns.
*   Enable `process_creation` logging for Linux systems to capture command-line arguments of processes like `zstd`.
*   Monitor for the creation of new files in system cron directories, specifically `/etc/cron.d/incus-zstd-rce`, using file integrity monitoring or `file_event` logging, as this indicates a successful arbitrary file write.
*   Block the arbitrary file write target `/etc/cron.d/incus-zstd-rce` from being created by non-system processes if possible, or create a `file_event` rule to alert on its creation.
