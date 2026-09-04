---
title: Abuse of Native Windows Utilities to Modify File Permissions
slug: 2026-09-icacls-deny-abuse
description: Adversaries leverage native utilities like icacls.exe to modify file and directory permissions via deny flags, effectively hindering security operations and maintaining persistence.
date: "2026-09-04T18:00:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - endpoint-security
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1222
    technique_name: File and Directory Permissions Modification
    evidence: The following analytic detects instances where an adversary modifies security permissions of a file or directory using commands like icacls.exe.
    confidence_band: high
rules:
  - title: Detect Unauthorized File Permission Denial via icacls
    description: Detects the use of icacls, cacls, or xcacls with deny flags which can be used to impede security tools and incident response.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1222
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for icacls/cacls/xcacls usage with deny flags.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line patterns for identification.
  hunt_leads:
    - lead: Search for instances of icacls.exe usage combined with /deny flags in historical EDR logs.
      technique_id: T1222
      data_needed:
        - Endpoint process logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Technique is frequently used by APTs and miners for defense evasion.
---

Threat actors, including Advanced Persistent Threats (APTs) and operators of malicious payloads such as coinminers, frequently utilize native Windows file permission utilities to facilitate defense evasion. By executing commands using icacls.exe, cacls.exe, or xcacls.exe with deny flags (e.g., /deny, /d), adversaries can strip administrative or security software access from specific directories or files. This behavior is specifically intended to impede incident response efforts, disrupt security agents, and secure malicious components from deletion or inspection. Defenders should prioritize visibility into process execution command-line arguments to identify unauthorized modifications to system or application directory access control lists.

## Impact

Successful execution of these commands allows attackers to effectively hide malicious artifacts, prevent security software from accessing or scanning critical files, and maintain long-term persistence within a compromised host. This technique is commonly observed in the aftermath of initial access to prevent automated cleanup or manual remediation by security teams.

## Recommendation

Prioritize the implementation of process-creation logging to capture full command-line arguments for file-permission manipulation tools. Deploy the Sigma rules below to monitor for suspicious usage of deny-access flags. Investigate any instances where these utilities are invoked by processes other than system installers or configuration management tools.
