---
title: Suspicious Output Redirection to Local Admin Shares
slug: 2026-09-suspicious-admin-share-redirection
description: Attackers utilize output redirection to local administrative shares as a stealthy method to stage malicious scripts or tools within a compromised environment.
date: "2026-09-03T12:45:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - exfiltration
  - lateral-movement
  - persistence
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: This technique is often found in malicious scripts or hacktool stagers.
    confidence_band: high
references:
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
  - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
rules:
  - title: Detect Suspicious Redirection to Local Admin Share
    description: Detects a suspicious output redirection to the local admins share, this technique is often found in malicious scripts or hacktool stagers
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1048
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
    - action: Deploy Sigma rule to monitor for redirection to admin shares
      owner: Detection Engineering
      due: 24h
      evidence: Source provides detection logic for malicious script/stager behavior
  hunt_leads:
    - lead: Process creations containing redirection operators and admin share paths
      technique_id: T1048
      data_needed:
        - CommandLine
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Sigma rule provided in source
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict ACLs on administrative shares to limit write access
      owner: IT Operations
      addresses: Technique T1048
      evidence: Admin share abuse is a documented persistence and staging vector
---

Adversaries often use output redirection (the '>' operator) to write the output of malicious scripts or command-line tools to local administrative shares, such as ADMIN$. This technique is frequently employed by threat actors, including those linked to destructive malware campaigns and state-sponsored espionage, to facilitate the staging of tools, exfiltration of data, or persistence across systems. By redirecting output directly to these shares, attackers can bypass typical directory monitoring and place malicious files in locations where they may be executed by automated tasks or system processes. Defenders should monitor for command lines that combine redirection operators with local loopback addresses targeting administrative shares, as this behavior is rarely observed in standard administrative or user activity.

## Attack Chain

1. Initial access is established via exploitation or phishing to gain code execution.
2. The attacker identifies a target system for lateral movement or persistence.
3. A malicious payload, script, or stager is prepared for execution.
4. The attacker executes a command, such as 'cmd.exe' or 'powershell.exe', with an output redirection parameter.
5. The command directs the execution output or tool data to the local ADMIN$ share (e.g., '\\\\127.0.0.1\\admin$\\stage.tmp').
6. The redirected file is accessed or executed via subsequent remote or local commands.
7. The objective, such as credential harvesting, malware deployment, or system sabotage, is achieved.

## Impact

This technique enables the clandestine staging of malware and malicious tools within a target environment. Success allows attackers to maintain persistence, escalate privileges, and execute further lateral movement, potentially leading to widespread system destruction or long-term data exfiltration.

## Recommendation

- Deploy the Sigma rule below to detect suspicious redirection patterns in command-line arguments.
- Enable Sysmon process creation logging (Event ID 1) to capture the necessary command-line parameters for analysis.
- Review all logs flagging redirection to ADMIN$ or C$ for unauthorized tool staging.
- Restrict access to administrative shares through GPO or host-based firewalls to prevent unauthorized write operations by non-administrative users.
