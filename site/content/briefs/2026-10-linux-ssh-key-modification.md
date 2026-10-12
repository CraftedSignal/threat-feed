---
title: Detection of Linux SSH Authorized Keys Modification
slug: 2026-10-linux-ssh-key-modification
description: Adversaries modify SSH authorized_keys files on Linux systems to establish persistent access and bypass authentication, a technique detectable through process execution monitoring.
date: "2026-10-12T17:51:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - linux
  - e-crime
  - cloud-native
  - lotl
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries often modify SSH Authorized Keys to establish persistent access to compromised endpoints.
    confidence_band: high
references:
  - https://redcanary.com/blog/lateral-movement-with-secure-shell/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.004/T1098.004.md
rules:
  - title: Detect Linux SSH Authorized Keys Modification
    description: Detects the modification of SSH authorized_keys files using common tools like bash or cat, which is a known technique for establishing persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.004
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
    - action: Deploy Sigma rule for authorized_keys modification
      owner: Detection Engineering
      due: 48h
      evidence: Analytic requirement defined in source
  hunt_leads:
    - lead: Audit existing authorized_keys files for unauthorized public keys
      technique_id: T1098.004
      data_needed:
        - File integrity logs or manual audit of .ssh/authorized_keys
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Standard practice for identifying unauthorized persistence
  mitigation_plan:
    - priority: short_term
      action: Enforce strict file permissions (600) on .ssh/authorized_keys
      owner: IT Operations
      addresses: T1098.004
      evidence: Standard Linux security hardening
---

Adversaries frequently target the Linux ~/.ssh/authorized_keys file to establish persistent access to compromised endpoints. By injecting their own public keys into this file, attackers can bypass standard authentication mechanisms and maintain long-term unauthorized access to the system. This technique is often observed as part of broader campaigns involving Living off the Land (LotL) binaries, as well as specific threat activities attributed to malware like Hellcat Ransomware and VoidLink. Defenders must monitor process execution telemetry for common command-line tools interacting with these configuration files to identify potential persistence creation.

## Impact

Successful modification of authorized_keys allows an attacker to maintain persistent, high-privilege access to the target host. This unauthorized access can lead to lateral movement, further exploitation, or long-term data exfiltration. The technique is a common component of modern Linux-based threats, including those linked to ransomware operations and cloud-native malware deployments.

## Recommendation

Prioritize detection engineering efforts to monitor process execution paths targeting SSH configuration files.

- Deploy the Sigma rule below to monitor for process activity interacting with authorized_keys files.
- Implement filtering to exclude benign system administration activity, such as legitimate key management scripts utilizing 'echo' or 'ssh-keygen'.
- Configure Sysmon for Linux (Event ID 1) to capture full process command lines and parent process information.
- Use the provided drilldown search logic to investigate specific users and destinations associated with detected key modifications.
