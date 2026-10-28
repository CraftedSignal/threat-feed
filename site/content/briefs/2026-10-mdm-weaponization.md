---
brief_id: brief-2026-10-28-mdm-weaponization
event_id: brief-2026-10-28-mdm-weaponization
revision: 1
activity_at: "2026-10-28T17:43:32Z"
title: Threat Actors Weaponizing MDM Platforms for Persistent Access
slug: 2026-10-mdm-weaponization
description: Threat actors are leveraging social engineering to enroll devices into legitimate MDM platforms like Hexnode and Rippling to gain privileged access and maintain persistence via unauthorized RMM deployment.
date: "2026-10-28T17:43:32Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - phishing
  - mdm-abuse
  - rmm
  - persistence
  - initial-access
vendors:
  - Hexnode
  - Rippling
  - ConnectWise
products:
  - Hexnode MDM
  - Rippling MDM
  - ScreenConnect
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: The attack began with a phishing email.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    subtechnique_id: T1543.003
    subtechnique_name: Windows Service
    evidence: They simply staged and installed the RMM software again.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.001
    subtechnique_name: Web Protocols
    evidence: The threat actor followed up by installing ScreenConnect shortly thereafter and connecting to the attacker-controlled relay.
    confidence_band: high
references:
  - https://www.huntress.com/blog/attackers-turn-mdm-into-remote-access
iocs:
  - type: url
    value: https://webdocusign.viewportal.es/Windows/download/index.php
  - type: domain
    value: relay.bobdthjau.com
ioc_counts:
  domain: 1
  url: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all registered devices within your MDM environments to ensure all enrollments are authorized.
      owner: IT Operations
      due: 24h
      evidence: Huntress is seeing attackers abusing legitimate MDM platforms.
    - action: Review and block the IOCs provided in this brief at the network perimeter.
      owner: SOC
      due: 4h
      evidence: Source observed ScreenConnect connections to relay.bobdthjau.com.
  hunt_leads:
    - lead: Search MDM platform activity logs for unauthorized or unexpected enrollment events within the last 30 days.
      technique_id: T1133
      data_needed:
        - MDM audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Huntress is seeing attackers abusing legitimate MDM platforms.
  mitigation_plan:
    - priority: immediate
      action: Remove unauthorized RMM agents (e.g., ScreenConnect) and concurrently audit/revoke the associated MDM enrollment that facilitated the installation.
      owner: IT Operations
      addresses: ScreenConnect persistence via MDM
      evidence: Removing the RMM did little to deter them. They simply staged and installed the RMM software again.
---

Threat actors are weaponizing legitimate Mobile Device Management (MDM) platforms, specifically Hexnode and Rippling, to gain unauthorized remote access. This activity involves social engineering users via business-themed phishing lures to trick them into installing an MDM agent. Once enrolled, the actor uses the MDM platform's native, trusted capabilities to deploy and re-deploy rogue Remote Monitoring and Management (RMM) tools, such as ScreenConnect. This mechanism allows the attacker to maintain persistence even after security teams remove individual RMM instances.

## Attack Chain

1. **Phishing:** Users receive business-themed emails with subjects like "ATTN: Official Invitation to Submit Proposal."
2. **Delivery:** The emails contain links to a malicious domain.
3. **Download:** A file (e.g., eD0cuSign_Installer.msi) is downloaded to the user's browser temporary folder.
4. **Execution:** The user executes the MSI, which installs a legitimate MDM agent (Hexnode) while masquerading as a different application (e.g., DocuSign).
5. **Enrollment:** The device is registered to an attacker-controlled MDM instance.
6. **Persistence:** The attacker uses the MDM platform to deploy or re-deploy unauthorized RMM software (ScreenConnect).
7. **Command and Control:** The RMM agent connects to an attacker-controlled relay server.

## Impact

The use of legitimate MDM platforms provides attackers with an authenticated, privileged pathway to the system. This allows for persistent remote control that survives initial remediation attempts, as the MDM agent can automatically re-install removed RMM software.

## Recommendation

* Audit all MDM enrollments to identify unauthorized or rogue management agents.
* Monitor for the installation of unauthorized RMM tools, particularly ScreenConnect, which may be deployed via MDM commands.
* Review administrative logs of MDM platforms for anomalous enrollment patterns or unexpected deployment of remote access tools.
* Train users to verify the source of software installation packages, especially when they arrive via unexpected emails.
