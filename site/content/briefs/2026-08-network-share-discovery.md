---
title: Detection of Administrative SMB Share Access via Dir Command
slug: 2026-08-network-share-discovery
description: This detection targets the use of the 'dir' command to access sensitive Windows administrative SMB shares (Admin$, IPC$, C$), a behavior often utilized by attackers for lateral movement and staging of malicious tools.
date: "2026-08-05T21:12:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - discovery
  - smb
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1135
    technique_name: Network Share Discovery
    evidence: The following analytic detects access to Windows administrative SMB shares (Admin$, IPC$, C$) using the 'dir' command.
    confidence_band: high
rules:
  - title: Detect Administrative SMB Share Access via Dir Command
    description: Detects read access to administrative SMB shares (Admin$, IPC$, C$) which is often a precursor to lateral movement using tools like PsExec.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1135
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
    - action: Enable Windows Security Event ID 5140 collection
      owner: IT Operations
      due: 72h
      evidence: Source requirement for detection
  hunt_leads:
    - lead: Analyze Event ID 5140 for connections to sensitive shares from non-IT subnets
      technique_id: T1135
      data_needed:
        - EventID 5140 logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation on PsExec staging techniques
  mitigation_plan:
    - priority: medium_term
      action: Restrict administrative share access via host-based firewalls
      owner: IT Operations
      addresses: T1135
      evidence: Standard practice to limit lateral movement surface area
---

Adversaries frequently target Windows administrative SMB shares, specifically Admin$, IPC$, and C$, to facilitate lateral movement and remote code execution within an enterprise environment. Tools like PsExec and PaExec leverage these shares to stage malicious binaries and create remote services. Attackers often use the simple 'dir' command to enumerate or confirm connectivity to these shares prior to deploying secondary payloads. This technique has been observed in campaigns such as the IcedID malware propagation, where attackers move laterally to infect multiple hosts. Defenders should monitor for unexpected access to these administrative shares, especially when originating from non-administrative sources or unexpected workstations, as this activity is a critical indicator of pre-exploitation reconnaissance and staging.

## Attack Chain

1. Attacker gains initial access to a compromised endpoint within the environment.
2. Attacker performs internal reconnaissance to identify reachable network assets.
3. Attacker uses the 'dir' command or similar utilities to verify connectivity to administrative shares (\\Admin$, \\C$, \\IPC$) on target hosts.
4. Attacker copies malicious binaries or lateral movement tools to the identified administrative shares.
5. Attacker creates a new service or modifies an existing service on the remote target to execute the staged binary.
6. Attacker establishes persistent or remote execution access on the target system.
7. Attacker proceeds with further malicious objectives, such as credential theft or ransomware deployment.

## Impact

Successful exploitation of this technique enables attackers to move laterally through the network, escalate privileges, and deploy malware such as IcedID or ransomware. This can lead to significant operational disruption, widespread lateral infection, and potential data exfiltration across the organization.

## Recommendation

Prioritize the identification of abnormal SMB share access patterns in the environment by ingesting Windows Security Event ID 5140 logs. Enable Object Access Auditing in Group Policy to ensure these events are generated. Deploy the following Sigma rule and filter out known legitimate administrative service accounts or automated system management tools to reduce false positives.
