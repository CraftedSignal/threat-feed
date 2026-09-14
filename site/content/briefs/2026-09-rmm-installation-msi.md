---
title: Detection of RMM Software Deployment via Internet-Originated MSI Files
slug: 2026-09-rmm-installation-msi
description: This detection identifies the download and execution of Windows Installer (MSI) packages from the internet that result in the installation of remote monitoring and management (RMM) software used for persistent system access.
date: "2026-09-14T12:54:37Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - command-and-control
  - windows
  - rmm
vendors:
  - Acronis
  - AeroAdmin
  - AnyDesk
  - APC
  - Atera
  - AweSun
  - Barracuda
  - BeyondTrust
  - CloudRadial
  - ConnectWise
  - Devolutions
  - Domotz
  - DWService
  - GetScreen
  - GoTo
  - HelpWire
  - ImmyBot
  - Impero
  - ISLOnline
  - JumpCloud
  - Kaseya
  - Komari
  - Level
  - LogMeIn
  - Lunixar
  - ManageEngine
  - MeshCentral
  - Mikogo
  - Nezha
  - NinjaOne
  - Parsec
  - PDQ
  - Pulseway
  - Microsoft
  - Radmin
  - RealVNC
  - Remotely
  - RemotePC
  - RemoteUtilities
  - RPCSuite
  - Rsupport
  - RustDesk
  - SimpleHelp
  - Splashtop
products:
  - Acronis Cyber Protect Connect
  - AeroAdmin
  - AnyDesk
  - APC Admin
  - Atera Agent
  - AweSun
  - Barracuda RMM
  - BeyondTrust Remote Support
  - CloudRadial
  - ConnectWise Automate
  - Devolutions Remote Desktop Manager
  - Domotz Agent
  - DWService
  - GetScreen
  - GoToAssist
  - HelpWire
  - ImmyBot
  - Impero
  - ISL Online
  - JumpCloud Agent
  - Kaseya VSA
  - Komari Agent
  - Level Agent
  - LogMeIn Rescue
  - Lunixar
  - ManageEngine Remote Access Plus
  - MeshCentral
  - Mikogo
  - Nezha Agent
  - NinjaOne RMM
  - Parsec
  - PDQ Connect
  - Pulseway
  - Quick Assist
  - Radmin
  - RealVNC
  - Remotely
  - RemotePC
  - Remote Utilities
  - RPCSuite
  - RemoteView
  - RustDesk
  - SimpleHelp
  - Splashtop
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Attackers use RMMs commonly in social engineering campaigns to gain access and control over the victim's system, often utilizing msiexec to execute installers.
    confidence_band: high
references:
  - https://www.proofpoint.com/us/blog/threat-insight/remote-monitoring-and-management-rmm-tooling-increasingly-attackers-first-choice
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-131a
  - https://cloud.google.com/blog/topics/threat-intelligence/seo-poisoning-batloader-atera/
  - https://www.microsoft.com/en-us/security/blog/2026/03/03/signed-malware-impersonating-workplace-apps-deploys-rmm-backdoors/
  - https://www.huntress.com/blog/series-of-unfortunate-rmm-events
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection for internet-originated MSI execution correlating to RMM agent creation.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific ESQL rule and correlation logic for RMM-related MSI activity.
  hunt_leads:
    - lead: Identify all MSI executions where the file origin URL domain is not in the organization's approved allowlist.
      technique_id: T1218.007
      data_needed:
        - Endpoint file creation events (origin URL)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source highlights RMM installers frequently originating from uncurated internet sources.
  mitigation_plan:
    - priority: short_term
      action: Restrict the execution of MSI files to those signed by trusted organization certificates or deployed via authorized management tools.
      owner: IT Operations
      addresses: RMM persistence via MSI
      evidence: Source notes that managed deployments are the primary legitimate use case.
---

Security analysts have observed an increase in threat actors leveraging legitimate Remote Monitoring and Management (RMM) tools as a primary means of establishing persistent, unauthorized remote access to victim environments. Attackers often deliver these tools through social engineering campaigns, where users are induced to download and run seemingly benign MSI installers from the internet. When executed, these packages deploy various RMM agents that grant the actor full administrative control over the compromised endpoint.

Because RMM tools are dual-use software, their presence is not inherently malicious, complicating detection efforts. This intelligence focuses on identifying the specific activity chain where a file of type .msi, originating from a non-reputable internet location, is executed via the Windows Installer process (msiexec.exe), followed shortly by the creation of known RMM-related service or agent executables. Defenders should treat such sequences as potential unauthorized persistence attempts, particularly when the installation was not initiated through managed IT or internal software distribution channels.

## Impact

Successful deployment of RMM tools by unauthorized actors leads to complete loss of confidentiality and integrity on the impacted host. Attackers use these tools for file exfiltration, remote command execution, and as a springboard for further lateral movement within corporate networks. These campaigns have been observed across various sectors as attackers aim to maintain long-term, stealthy access to internal resources.

## Recommendation

Detection engineering teams should implement monitoring for the specific sequence of MSI execution followed by RMM agent creation.

* Deploy the provided ESQL detection logic to identify the correlation between internet-sourced MSI downloads and RMM binary creation.
* Establish a baseline for authorized IT RMM deployment to differentiate legitimate administrative activity from unauthorized installations.
* Block or monitor downloads from untrusted domains that frequently host these installers, particularly those outside of known developer artifact and cloud storage services.
* Audit endpoint logs to verify the parent process for all msiexec.exe executions to ensure they align with established software deployment policies.
