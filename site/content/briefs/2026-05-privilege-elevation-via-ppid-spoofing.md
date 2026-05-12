---
title: Privilege Elevation via Parent Process PID Spoofing
slug: 2026-05-privilege-elevation-via-ppid-spoofing
description: This rule detects parent process spoofing used to create an elevated child process, specifically targeting privilege escalation to SYSTEM, where adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges on Windows systems.
date: "2026-05-12T19:10:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - ppid-spoofing
vendors:
  - Elastic
  - philandro Software GmbH
  - Freedom Scientific Inc.
  - TeamViewer Germany GmbH
  - Projector.is, Inc.
  - TeamViewer GmbH
  - Cisco WebEx LLC
  - Dell Inc
  - HEAT Software
  - VisualCron
  - BinaryDefense
  - Wacom
  - LogMeIn
  - EMC Captiva
  - Google
  - Netwrix Corporation
products:
  - Elastic Endpoint
  - Chrome Remote Desktop
  - GoToAssist Remote Support Customer
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_via_ppid_spoofing.toml
  - https://gist.github.com/xpn/a057a26ec81e736518ee50848b9c2cd6
  - https://blog.didierstevens.com/2017/03/20/that-is-not-my-child-process/
  - https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1134.002/T1134.002.md
rules:
  - title: Detect PPID Spoofing - Elevated Child Process with Mismatched Parent PID
    description: Detects an elevated child process (SYSTEM) where the reported parent PID does not match the real creator PID, indicative of PPID spoofing.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1134.002
    data_sources:
      - process_creation
      - windows
  - title: Detect PPID Spoofing - Process Creation via Seclogon with SYSTEM Privileges
    description: Detects process creation via seclogon service with SYSTEM privileges, indicating potential PPID spoofing.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1134.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies a technique known as parent process ID (PPID) spoofing used to elevate privileges on Windows systems. PPID spoofing involves creating a new process with a spoofed parent process ID to evade process monitoring defenses or gain higher privileges. This is achieved by manipulating the `UpdateProcThreadAttribute` API. The detection specifically looks for processes running as SYSTEM (`user.id : "S-1-5-18"`) where the real parent PID (`process.parent.Ext.real.pid`) differs from the reported parent PID, which could indicate spoofing. The rule aims to identify privilege escalation attempts while excluding common false positives like Windows Error Reporting, update processes, and certain third-party software. This behavior matters for defenders because successful PPID spoofing can allow attackers to execute malicious code with elevated privileges, potentially leading to complete system compromise.

## Attack Chain

1.  An attacker gains initial access to the system, potentially through exploitation of a vulnerability or social engineering.
2.  The attacker executes a malicious program or script designed to perform PPID spoofing.
3.  The malicious program uses the `UpdateProcThreadAttribute` API to set a custom parent process ID (PPID) for a new process.
4.  The attacker attempts to create a new process with SYSTEM privileges, often through the `seclogon` service. The new process inherits the spoofed PPID.
5.  The system creates the new process with the specified (spoofed) parent PID, while the `Ext.real.pid` reflects the true creator process.
6.  The spoofed process executes malicious commands, leveraging SYSTEM privileges. This could involve installing backdoors, modifying system configurations, or stealing sensitive data.
7.  The attacker attempts to move laterally within the network, utilizing the compromised system as a launchpad.
8.  The final objective could be data exfiltration, ransomware deployment, or long-term persistence within the environment.

## Impact

Successful PPID spoofing can grant attackers SYSTEM-level privileges, allowing them to perform virtually any action on the compromised system. This can lead to data theft, system corruption, or the installation of persistent backdoors. A single compromised system can serve as a beachhead for further attacks within the network. The potential damage includes significant financial losses, reputational damage, and disruption of business operations. The rule is designed to detect this activity before significant damage occurs by identifying the initial elevation of privileges via PPID spoofing.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect potential PPID spoofing attempts, focusing on the processes running as SYSTEM with mismatched parent PIDs (`process.parent.Ext.real.pid` vs `process.parent.pid`).
*   Enable process creation logging with full command-line auditing to capture the necessary data for the Sigma rules to function effectively.
*   Investigate any alerts generated by the Sigma rules by examining the parent and child processes, as well as the user context and command-line arguments.
*   Implement application control policies to restrict the execution of unauthorized or untrusted executables, mitigating the risk of malicious code execution via PPID spoofing.
*   Review and harden the configuration of systems with elevated privileges to minimize the potential impact of successful privilege escalation attacks.
*   Tune the Sigma rules based on your environment to reduce false positives by excluding known-benign processes and applications.
*   Consult the references for more context on PPID spoofing and mitigation strategies.
