---
title: BRICKSTORM Malware Targeting VMware vSphere Environments
slug: 2026-04-brickstorm-vsphere
description: The BRICKSTORM malware targets VMware vSphere environments, specifically vCenter Server Appliance (VCSA) and ESXi hypervisors, by exploiting weak security configurations to establish persistence at the virtualization layer, leading to administrative control and potential data exfiltration.
date: "2026-04-02T13:55:05Z"
severities:
  - critical
actors:
  - BRICKSTORM
tags:
  - vsphere
  - virtualization
  - brickstorm
  - persistence
  - lateral-movement
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/vsphere-brickstorm-defender-guide/
rules:
  - title: Detect Startup File Modification in Photon OS
    description: Detects modifications to startup files in Photon OS, commonly used for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.004
    data_sources:
      - file_event
      - linux
  - title: Detect SSH Login without Logging
    description: Detects SSH logins to the VCSA Photon OS without corresponding command logging, which indicates suspicious administrative access.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The BRICKSTORM campaign targets VMware vSphere environments, with a focus on the vCenter Server Appliance (VCSA) and ESXi hypervisors. This campaign, building on previous BRICKSTORM research, highlights the increasing threats targeting virtualized infrastructure. By gaining persistence at the virtualization layer, attackers bypass traditional security measures, such as endpoint detection and response (EDR) agents, which are often ineffective in these environments. The attackers exploit weak…
