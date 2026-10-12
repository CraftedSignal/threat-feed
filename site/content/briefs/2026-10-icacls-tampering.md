---
title: Windows File and Directory Permission Tampering via icacls.exe
slug: 2026-10-icacls-tampering
description: Adversaries, including those using Amadey malware, utilize Windows utilities like icacls.exe to modify file permissions, facilitating defense evasion and persistence by hindering security analysis.
date: "2026-10-12T18:07:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - acl-tampering
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1222.001
    technique_name: File and Directory Permissions Modification
    evidence: The following analytic identifies the modification of security permissions on files or directories using tools like icacls.exe, cacls.exe, or xcacls.exe.
    confidence_band: high
rules:
  - title: Detect Windows File Access Rights Modification via icacls
    description: Detects the use of icacls, cacls, or xcacls with command-line flags indicative of security permission modification
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1222.001
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
    - action: Deploy detection rule for icacls permission changes
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command-line indicators and TTP mapping.
  hunt_leads:
    - lead: Search for instances of icacls.exe, cacls.exe, or xcacls.exe executing with /grant, /deny, or /P flags in historical logs.
      technique_id: T1222.001
      data_needed:
        - Process creation logs with command lines
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Adversaries commonly use these tools to hide malicious files.
---

This threat involves the use of native Windows administrative utilities - specifically `icacls.exe`, `cacls.exe`, and `xcacls.exe` - to alter the security descriptors of files and directories on compromised endpoints. Attackers leverage these built-in tools to manipulate Access Control Lists (ACLs), effectively granting themselves privileged access, restricting security software from accessing malicious artifacts, or impeding incident response efforts. 

This activity is commonly observed during the execution phase of campaigns, such as those employing Amadey malware, where adversaries aim to protect their persistence mechanisms and data exfiltration tools from administrative discovery. By modifying permissions, actors can prevent security tools from reading, deleting, or remediating malicious files, thereby maintaining control over the compromised system. Monitoring for these specific command-line execution patterns is critical for identifying unauthorized modifications of system security posture.

## Attack Chain

1. Initial access is established on the victim endpoint (e.g., via phish or exploit).
2. Malware payload (e.g., Amadey) is executed on the target system.
3. The attacker drops secondary components or malicious artifacts into a directory.
4. The attacker executes `icacls.exe` to modify the security descriptor of the directory or file.
5. The command includes flags such as /grant, /deny, /P, or /E to change the access rights.
6. The modified permissions restrict access to the file for administrative or system accounts.
7. The attacker maintains persistence while protecting the malicious payload from investigation.

## Impact

Successful manipulation of file permissions can lead to a total loss of visibility for security operations teams and automated detection platforms. Attackers can prevent the deletion of malware, block forensic software from reading critical files, and preserve malicious persistence mechanisms. This technique is frequently observed across various campaigns, particularly where coinminers or infostealers are deployed, impacting the integrity of the endpoint and complicating recovery efforts for system administrators.

## Recommendation

* Deploy the provided Sigma rule to detect the execution of `icacls.exe` or `cacls.exe` with permission modification flags.
* Ingest Sysmon Event ID 1 or Windows Security Event 4688 logs into the SIEM to ensure command-line visibility.
* Enable process creation logging globally to capture the full command-line arguments used during permission changes.
* Tune detections against legitimate administrative activities, such as software installers or backup scripts, that may legitimately modify ACLs.
