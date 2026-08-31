---
title: Abuse of Application Compatibility Shim Databases for Persistence
slug: 2026-08-shim-persistence
description: Attackers utilize the Windows Application Compatibility Shim (AppCompat) mechanism to achieve persistence and arbitrary code execution by registering malicious shim databases.
date: "2026-08-31T17:52:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - windows
  - appcompat
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: This Windows functionality has been abused by attackers to stealthily gain persistence and arbitrary code execution in legitimate Windows processes.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_app_compat_shim.toml
  - https://attack.mitre.org/techniques/T1546/011/
rules:
  - title: Detect Custom Shim Database Installation
    description: Detects the installation of custom Application Compatibility Shim databases by monitoring registry changes to the AppCompatFlags subkeys.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.011
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided detection rule for registry modification monitoring
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit path and filter logic
  hunt_leads:
    - lead: Search for .sdb files registered in the AppCompatFlags registry keys not associated with known software
      technique_id: T1546.011
      data_needed:
        - Registry modification logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source defines the path and technique
---

The Windows Application Compatibility (AppCompat) framework is designed to allow legacy applications to function correctly on newer versions of the Windows operating system. This framework utilizes Shim Database (.sdb) files to apply compatibility fixes or patches to specific processes. Threat actors have been observed abusing this functionality to gain persistence and execute arbitrary code by installing custom, malicious shim databases. Once registered in the Windows Registry, these databases can force the loading of malicious code into legitimate processes whenever they are executed. This technique is particularly effective as it operates at the system level and can be used to achieve stealthy, persistent execution. Defenders should monitor registry modifications within the AppCompatFlags subtree to detect the registration of unauthorized .sdb files.

## Impact

Successful abuse of Application Compatibility Shim databases allows attackers to achieve persistent execution with the privileges of the host process, potentially leading to unauthorized access, privilege escalation, or data exfiltration. This technique can be applied across various Windows environments, and its stealthy nature makes it a valuable persistence mechanism for threat actors seeking to maintain long-term access to compromised systems.

## Recommendation

- Deploy the provided Sigma rule to monitor registry modifications within the 'AppCompatFlags\Custom\' registry key for the creation or modification of .sdb entries.
- Establish a baseline of legitimate shim database registrations within the environment to reduce false positives.
- Investigate any registry modification events originating from unknown or unsigned processes that target 'AppCompatFlags\Custom\'.
- Regularly audit system registry paths associated with 'AppCompatFlags' to identify and remove unauthorized or suspicious .sdb entries.
