---
title: Detection of GoToAssist Remote Support Temporary Artifacts
slug: 2026-09-gotoassist-temp-artefact
description: Adversaries often abuse legitimate remote access software like GoToAssist to establish interactive command-and-control channels, leaving specific temporary artifacts in the user's local profile.
date: "2026-09-03T13:36:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - remote-access
  - command-and-control
  - living-off-the-land
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_gotoopener_artefact.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-4---gotoassist-files-detected-test-on-windows
rules:
  - title: Detect GoToAssist Remote Support Temporary Files
    description: Detects the creation of temporary file artifacts associated with the GoToAssist Remote Support installation process.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to production SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific pathing for GoToAssist artifacts.
  hunt_leads:
    - lead: Search for instances of GoToAssist installer binaries in non-IT managed directories.
      technique_id: T1219
      data_needed:
        - Process creation logs
        - File system activity
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Tooling is often used for C2; searching for existence helps identify persistence.
---

Remote access tools such as GoToAssist are frequently leveraged by adversaries to maintain persistence and establish command-and-control (C2) channels within target networks. Because these tools are widely used for legitimate technical support and help-desk operations, they are often permitted by application control policies, allowing attackers to blend in with authorized administrative activity. During the execution of the GoToAssist remote support installer or the GoToOpener application, the software creates specific temporary files and directory structures within the user's AppData path. Detecting the creation of these specific artifacts serves as a high-fidelity signal for identifying the initialization of unauthorized remote access sessions in environments where such software should not be present or is restricted to specific, authorized IT accounts.

## Impact

Successful abuse of GoToAssist enables unauthorized remote interactive access to target endpoints. This provides an attacker with the ability to execute commands, transfer files, and interact with the desktop environment, facilitating data exfiltration, lateral movement, or the deployment of further malicious payloads. In many cases, this activity bypasses standard security controls that rely on blocking unknown or blacklisted remote access binaries.

## Recommendation

- Deploy the provided Sigma rule to monitor for the creation of GoToAssist-related temporary files within the user AppData directory.
- Implement application control or software restriction policies to block the execution of GoToAssist binaries by non-authorized users.
- Investigate any file creation events originating from the paths identified in the Sigma rule to determine if the activity is associated with a legitimate support session or unauthorized access.
