---
title: Monitoring Unauthorized Modifications to Sudoers Configuration
slug: 2026-09-sudoers-file-activity
description: Adversaries may attempt to escalate privileges on Unix-like systems by modifying the sudoers configuration file to grant unauthorized users or groups elevated permissions.
date: "2026-09-18T19:24:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - linux
  - macos
  - file-integrity
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Adversaries can take advantage of these configurations to execute commands as other users or spawn processes with higher privileges.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/privilege_escalation_sudoers_file_mod.toml
  - https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
rules:
  - title: Detect Unauthorized Modification of Sudoers File
    description: Detects unauthorized creation or modification of sudoers configuration files, excluding known benign administrative and configuration management processes.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548.003
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to endpoints.
      owner: Detection Engineering
      due: 48h
      evidence: Rule metadata for 931e25a5-0f5e-4ae0-ba0d-9e94eff7e3a4
  hunt_leads:
    - lead: Search for recent changes to /etc/sudoers where the modifying process is not an authorized management binary.
      technique_id: T1548.003
      data_needed:
        - File integrity logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source highlights sudoers modification as a primary indicator of privilege escalation.
  mitigation_plan:
    - priority: short_term
      action: Review and audit existing sudoers configurations and current access levels.
      owner: IT Operations
      addresses: Privilege escalation via sudo
      evidence: Investigation guide steps
---

The sudoers file is a critical component of security in Unix-like systems, defining user permissions and the ability to execute commands with elevated privileges. Because this file controls the execution of commands as other users or root, it is a high-value target for adversaries seeking to escalate their privileges or maintain persistent, elevated access. By modifying the sudoers file or its associated files (typically located in /etc/sudoers* or /private/etc/sudoers*), an attacker can grant themselves or a compromised service account unrestricted sudo rights. This activity is a common indicator of a Privilege Escalation (T1548.003) phase in a post-compromise attack chain. Defenders must distinguish these malicious modifications from legitimate changes made by configuration management systems (like Chef or Puppet) or system package managers (like apt/dpkg or yum).

## Impact

Successful modification of the sudoers file allows an attacker to achieve full root-level control of the compromised system. This impact includes the ability to bypass security controls, install persistence mechanisms, exfiltrate sensitive data, and move laterally throughout the network with elevated privileges. If not detected, an attacker can maintain long-term, unrestricted access to the host.

## Recommendation

1. Deploy the provided Sigma rule to monitor for unauthorized modifications to sudoers configuration files.
2. Baseline your environment by identifying and adding internal management tools or unique binary paths to the filter list to minimize false positives.
3. Ensure that file integrity monitoring is active on all Linux and macOS endpoints for the /etc/ and /private/etc/ directories.
4. Integrate these alerts into your SIEM's incident response workflow for immediate investigation of any unauthorized write events targeting sudoers.
