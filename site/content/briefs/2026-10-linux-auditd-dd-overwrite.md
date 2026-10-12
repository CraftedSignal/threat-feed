---
title: Detection of Linux Data Destruction via dd
slug: 2026-10-linux-auditd-dd-overwrite
description: Adversaries utilize the dd command to irreversibly overwrite system files with null bytes, facilitating data destruction and service disruption.
date: "2026-10-12T17:47:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - data-destruction
  - linux
  - auditd
  - impact
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Adversaries often use the 'dd' command to destroy or irreversibly overwrite files, disrupting system availability and services.
    confidence_band: high
rules:
  - title: Detect Linux dd Overwrite Activity
    description: Detects the use of the dd command to overwrite files using /dev/zero as the input source.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule and validate against Auditd log pipeline.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line flags for detection.
  hunt_leads:
    - lead: Search for historical execution of dd with if=/dev/zero across all Linux hosts.
      technique_id: T1485
      data_needed:
        - Auditd proctitle logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This activity is indicative of malicious data destruction attempts.
  mitigation_plan:
    - priority: medium
      action: Implement strict sudoers policies to restrict execution of destructive commands to authorized users.
      owner: IT Operations
      addresses: T1485
      evidence: Restricting execution reduces the likelihood of successful data destruction.
---

Adversaries targeting Linux environments frequently employ the 'dd' utility to perform destructive operations, specifically by overwriting sensitive system files, configuration files, or data partitions with null bytes from '/dev/zero'. This technique is a common method for achieving data destruction, which serves to disrupt operational continuity, disable security controls, or hinder forensic recovery efforts during an incident. By leveraging Linux Auditd telemetry, specifically the 'proctitle' field which records the full command line executed, security teams can detect the invocation of 'dd' with input files set to '/dev/zero' and specific output destinations. This behavior is highly irregular in standard administrative workflows and serves as a high-confidence indicator of malicious intent against system availability.

## Attack Chain

1. Attacker gains initial access to a Linux system via compromised credentials or an exploited service.
2. Attacker performs enumeration to identify critical system configuration files, database files, or log repositories.
3. Attacker evaluates system privileges to determine if the targeted files can be overwritten.
4. Attacker executes the 'dd' command with 'if=/dev/zero' to stream null data.
5. Attacker directs the output to a critical file or device using the 'of=' parameter.
6. The target file is effectively zeroed out, leading to data loss or system instability.
7. Attacker removes traces or clears logs to delay discovery.
8. Final objective is achieved: service denial and degradation of recovery capability.

## Impact

Successful execution of this destructive technique results in permanent data loss, system service failures, and significant operational disruption. It can render a system non-bootable or force an emergency rebuild, drastically increasing the mean time to recovery (MTTR) and impeding incident response activities.

## Recommendation

* Deploy monitoring for Linux Auditd 'proctitle' events specifically filtering for the execution of 'dd' with '/dev/zero' as the input source.
* Use the Sigma rule provided in this brief to alert on command-line patterns indicative of file overwriting.
* Tune detection logic by creating allowlists for known administrative automation scripts that legitimately use 'dd' for disk imaging or secure wiping in a controlled capacity.
* Ensure the Splunk Add-on for Unix and Linux is correctly configured to parse SYSCALL and PROCTITLE logs to maintain high fidelity of the 'proctitle' field.
