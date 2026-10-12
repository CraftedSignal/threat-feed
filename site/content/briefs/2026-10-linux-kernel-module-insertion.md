---
title: Detection of Linux Kernel Module Insertion via Insmod
slug: 2026-10-linux-kernel-module-insertion
description: This detection monitors for the execution of the 'insmod' utility on Linux systems, a technique frequently leveraged by attackers to deploy rootkits, gain kernel-level persistence, and escalate privileges.
date: "2026-10-12T17:49:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - rootkit
  - persistence
  - privilege-escalation
  - auditd
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The analytic detects the insertion of a Linux kernel module using the insmod utility.
    confidence_band: high
rules:
  - title: Detect Linux Kernel Module Insertion via insmod
    description: Detects the execution of the insmod utility to insert a kernel module, which may indicate the deployment of a rootkit or unauthorized kernel persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1547.006
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
    - action: Deploy Sigma rule for insmod process monitoring
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic guidance
  hunt_leads:
    - lead: Search for insmod execution in historical auditd logs
      technique_id: T1547.006
      data_needed:
        - Auditd SYSCALL logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: insmod usage is a high-signal indicator of kernel-level changes
---

The insertion of malicious Linux kernel modules (LKMs) is a sophisticated post-exploitation technique used to achieve deep persistence and gain elevated privileges. By loading a module directly into the kernel space, an attacker can effectively intercept system calls, hide processes, and blind security telemetry. The 'insmod' utility is a standard tool used to load these modules into the Linux kernel. Monitoring for 'insmod' usage via Linux Auditd syscall logs provides a critical opportunity to detect unauthorized kernel modifications. While legitimate administrators may occasionally use 'insmod' for driver troubleshooting or system maintenance, any unexpected execution, especially on production servers, warrants immediate investigation to ensure it is not a rootkit deployment.

## Impact

Successful deployment of a malicious kernel module results in total system compromise. Attackers can achieve kernel-mode execution, bypass all user-space security controls, disable logging, and establish near-permanent persistence that survives standard reboots and security software updates. This technique is often associated with advanced Linux malware families such as XorDDos and various custom rootkits.

## Recommendation

Deploy detection for 'insmod' process execution and perform the following actions:
- Enable Linux Auditd on all critical infrastructure nodes to log system calls (SYSCALL, EXECVE).
- Implement the provided Sigma rule to alert on 'insmod' process execution.
- Baseline authorized administrator activity to filter out legitimate kernel module management scripts.
- Review all kernel-level modifications for unauthorized binaries or unexpected modules loaded into memory.
