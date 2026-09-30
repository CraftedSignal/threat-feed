---
title: Phishing Campaigns Abusing MSP360 RMM for Persistent Access
slug: 2026-09-phishing-rmm-abuse
description: Threat actors are distributing masqueraded MSP360 RMM installers via phishing to establish persistent access and deploy secondary ScreenConnect remote-access channels for post-compromise activity.
date: "2026-09-30T01:17:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - rmm
  - persistence
  - remote-access
vendors:
  - MSP360
  - ConnectWise
products:
  - MSP360 RMM (v2.5.0.67)
  - ScreenConnect
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Microsoft observed phishing campaigns that used a multi-stage delivery chain to distribute legitimate, digitally signed MSP360 RMM software.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Upon user interaction, victims were redirected to download locations hosted on both attacker-controlled infrastructure and legitimate cloud services.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Next, the installer invoked a Windows User Account Control (UAC) elevation workflow.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: 'To establish long-term access on the affected device, the installer registered two Windows services: RMM.Agent.exe & RMM.Agent.Launcher.exe.'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Microsoft observed the MSP360 deployment being used to download and install a ConnectWise ScreenConnect client, creating a secondary remote-access channel.
    confidence_band: high
iocs:
  - type: hash_sha256
    value: 108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc
ioc_counts:
  hash_sha256: 1
rules:
  - title: Detect Suspicious MSP360 RMM Installation
    description: Detects the execution of MSP360 RMM components that may indicate a malicious deployment from an untrusted source or location.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
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
    - action: Block the identified SHA256 hash across all endpoints.
      owner: SOC
      due: 24h
      evidence: Source provides confirmed malicious payload hash.
  enrichment_needed:
    - item: Infrastructure URLs
      owner: CTI
      reason: Further identification of specific attacker-controlled landing pages.
      evidence: Source mentions use of S3, GitLab, and Dropbox.
  hunt_leads:
    - lead: Search for instances of MSP360 or ScreenConnect services registered on endpoints not associated with IT administrative tasks.
      technique_id: T1219
      data_needed:
        - Endpoint service registry logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source notes actor establishes persistence via RMM agent services.
  mitigation_plan:
    - priority: immediate
      action: Implement application control policies to restrict unauthorized RMM installation.
      owner: IT Operations
      addresses: T1219
      evidence: Source highlights RMM abuse as a persistent access technique.
---

Since July 2026, threat actors have conducted phishing campaigns to deploy legitimate, digitally signed MSP360 RMM (v2.5.0.67) software. These campaigns utilize diverse social-engineering lures, including fake meeting invitations, PDF-themed documents, and software update prompts, directing users to download payloads from legitimate cloud-hosted services such as Amazon S3, GitLab, and Dropbox. 

Once executed, the installer requests UAC elevation. Upon success, it establishes persistent access through Windows services and utilizes the RMM agent to silently install ConnectWise ScreenConnect. This creates a secondary, redundant remote-administration channel that allows attackers to blend in with legitimate IT operations. The established access is subsequently used to deploy additional tooling for credential harvesting and data collection. The use of trusted, legitimate RMM software significantly reduces detection opportunities as the activity mirrors standard administrative workflows. Organizations are advised to monitor for unauthorized or uncommon use of RMM binaries in their environments.

## Attack Chain

1. Phishing lures delivered via email direct victims to actor-controlled landing pages masquerading as collaboration or document portals.
2. Victims download a masqueraded, digitally signed MSP360 RMM (v2.5.0.67) installer with a deceptive filename.
3. The installer executes from the Downloads directory and drops helper components (System.dll, nsExec.dll, UAC.dll) to the local disk.
4. The installer triggers a UAC elevation prompt to gain administrative privileges.
5. Upon elevation, the installer registers 'RMM.Agent.exe' and 'RMM.Agent.Launcher.exe' as Windows services for persistent access.
6. The RMM agent is instructed via the attacker to invoke PowerShell for downloading and silently installing a ConnectWise ScreenConnect client.
7. The threat actor uses the redundant ScreenConnect remote-access channel to deploy post-exploitation tools.
8. Final objectives, including credential access and information collection, are executed via the remote-management channels.

## Impact

The abuse of legitimate RMM software allows actors to maintain long-term, persistent access to compromised endpoints. By creating redundant remote-access channels (MSP360 and ScreenConnect), attackers ensure continued visibility and control even if one channel is discovered or disabled. Successful compromises lead to sensitive data theft and credential harvesting, potentially escalating to broader network intrusion and lateral movement.

## Recommendation

* Deploy the Sigma rules provided in this brief to detect the execution of MSP360 or ScreenConnect binaries originating from unusual locations or processes.
* Block or restrict the use of unauthorized RMM software; create an allowlist of approved RMM agents and monitor for any deviation in process paths or file hashes.
* Enable enhanced monitoring for 'eventcreate.exe' and PowerShell execution associated with service installation, as observed during the MSP360 setup process.
* Monitor DNS and proxy logs for connections to known RMM distribution hosting sites (S3, Dropbox, GitLab, etc.) when initiated by user-executed binaries from the Downloads folder.
