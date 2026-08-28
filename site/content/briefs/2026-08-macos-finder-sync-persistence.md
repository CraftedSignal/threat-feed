---
title: Abuse of macOS Finder Sync Plugins for Persistence
slug: 2026-08-macos-finder-sync-persistence
description: Adversaries leverage the macOS Finder Sync plugin mechanism to maintain persistence by using the 'pluginkit' utility to register and enable malicious extensions.
date: "2026-08-28T21:07:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - macos
  - persistence
  - persistence-mechanism
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Adversaries may abuse this feature by adding a rogue Finder Plugin to repeatedly execute malicious payloads for persistence.
    confidence_band: high
references:
  - https://github.com/specterops/presentations/raw/master/Leo%20Pitt/Hey_Im_Still_in_Here_Modern_macOS_Persistence_SO-CON2020.pdf
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/persistence_finder_sync_plugin_pluginkit.toml
rules:
  - title: Detect Suspicious Finder Sync Plugin Registration
    description: Detects the use of pluginkit to register a Finder Sync plugin from a potentially malicious or unsigned parent process.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect unauthorized plugin registration
      owner: Detection Engineering
      due: 48h
      evidence: Source detection logic
  hunt_leads:
    - lead: Review pluginkit process logs for registrations originating from non-standard directories
      technique_id: T1543
      data_needed:
        - process_creation
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: pluginkit usage for persistence
  mitigation_plan:
    - priority: medium
      action: Implement strict code signing and notarization requirements for all managed macOS devices
      owner: IT Operations
      addresses: T1543
      evidence: OS-level security best practices
---

Adversaries targeting macOS environments may abuse the Finder Sync plugin feature to achieve persistence. Finder Sync plugins are legitimate components designed to extend the Finder's functionality and modify the user interface. By registering a rogue plugin, an attacker can ensure their malicious code is executed repeatedly by the system. This activity is typically performed via the 'pluginkit' command-line utility, which is used to manage system extensions. Monitoring the invocation of 'pluginkit' with specific arguments, especially when triggered by unauthorized parent processes or processes lacking valid code signatures, is a key detection strategy for security teams. This technique allows attackers to persist across reboots and user logons by masquerading as legitimate UI extensions.

## Impact

Successful exploitation allows for long-term persistence on macOS endpoints, facilitating ongoing command and control, data exfiltration, or the deployment of secondary malicious payloads. The impact is limited to the local system unless the plugin facilitates further lateral movement or privilege escalation.

## Recommendation

1. Deploy EDR-based detection to monitor the execution of the 'pluginkit' binary.
2. Baseline authorized Finder Sync plugins in your environment to distinguish them from rogue registrations.
3. Investigate parent process lineage for all 'pluginkit' executions, prioritizing alerts triggered by script interpreters like 'python', 'node', or 'osascript'.
4. Perform periodic audits of registered plugins using the 'pluginkit -m' command to identify unauthorized or unexpected extensions.
5. Enforce code signing policies for applications deployed to enterprise macOS endpoints.
