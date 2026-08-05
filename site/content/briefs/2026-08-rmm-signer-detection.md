---
title: Detection of Novel RMM Software Usage
slug: 2026-08-rmm-signer-detection
description: This brief details a detection strategy for identifying the introduction of remote monitoring and management (RMM) software in Windows environments by monitoring for newly observed code-signing certificates.
date: "2026-08-05T01:56:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - rmm
  - command-and-control
  - windows
  - endpoint-detection
vendors:
  - Action1
  - Aeroadmin
  - AmidaWare
  - Ammyy
  - AnyDesk Software
  - AOMEI
  - Atera Networks
  - AWERAY
  - BeamYourScreen
  - Bomgar
  - BreakingSecurity
  - ConnectWise
  - Devolutions
  - DOMOTZ
  - DUC FABULOUS
  - DWSNET
  - Electronic Team
  - Famatech
  - FleetDeck
  - GlavSoft
  - GoTo Technologies
  - Hefei Pingbo Network Technology
  - IDrive
  - Impero Solutions
  - Instant Housecall
  - ISL Online
  - JumpCloud
  - Level Software
  - LogMeIn
  - LUNIXAR
  - MMSOFT Design
  - N-ABLE
  - Nanosystems
  - NetSupport
  - NinjaOne
  - Parallels International
  - philandro Software
  - Pro Softnet
  - RealVNC
  - REMOTE UTILITIES
  - Rocket Software
  - Rsupport
  - Servably
  - ShowMyPC
  - SimpleHelp
  - Splashtop
  - Superops
  - Tailscale
  - TeamViewer
  - Techinline
  - uvnc
  - ZOHO
products:
  - RMM Software
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers often use RMM tools to gain remote access to victim machines and deploy malware.
    confidence_band: high
references:
  - https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
  - https://www.cisa.gov/sites/default/files/2025-06/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf
  - https://lolrmm.io/
rules:
  - title: Detect First Time Seen RMM Signer
    description: Detects the first execution of a process signed by a known RMM vendor certificate within the Windows environment.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1059.003
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
    - action: Deploy RMM signer detection rule.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific signer list for detection.
  enrichment_needed:
    - item: RMM vendor certificate list
      owner: CTI
      reason: Ensure list is current and relevant to organizational footprint.
      evidence: Source provided initial list.
  hunt_leads:
    - lead: Process creations signed by RMM certificates
      technique_id: T1059
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source details RMM abuse patterns.
  mitigation_plan:
    - priority: medium
      action: Enforce application control/allowlisting for remote access software.
      owner: IT Operations
      addresses: Unauthorized RMM usage.
      evidence: Source identifies RMM abuse.
---

Threat actors frequently abuse legitimate Remote Monitoring and Management (RMM) tools to gain unauthorized remote access, maintain persistence, and deploy secondary malware. By utilizing signed, legitimate administrative software, attackers often evade signature-based security controls and blend in with authorized IT management activity.

The provided detection logic identifies the first-time execution of processes associated with a curated list of RMM vendor code-signing certificates across an Elastic Defend-monitored Windows fleet. Because many of these vendors also produce non-remote-access software, the appearance of a new signer does not inherently indicate malicious activity. Defenders must investigate the parent process context, network activity, and child process execution to distinguish between authorized administrative deployments and the initial staging phase of a compromise.

## Impact

Successful abuse of RMM tools can provide an attacker with interactive control over a victim machine, enabling data exfiltration, lateral movement, and the deployment of ransomware. Because RMM software is designed for high-privilege access and visibility, compromise of these tools can result in widespread enterprise impact, potentially affecting an entire network if the RMM infrastructure is leveraged for domain-wide administrative operations.

## Recommendation

Detection engineering teams should implement the following actions to monitor for unauthorized RMM usage:

- Deploy the provided Sigma rule (or equivalent EDR query) to identify the first execution of binaries signed by known RMM vendor certificates.
- Establish a baseline of authorized RMM software currently used within the environment to filter out legitimate administrative tools from alerts.
- Enable process-creation logging and cross-reference process execution with known change management and software rollout schedules.
- Audit network egress traffic originating from RMM binary processes to identify connections to unauthorized or anomalous command-and-control infrastructure.
- Review child process activity for administrative tools; focus on unauthorized use of shells (cmd.exe, powershell.exe) or discovery utilities (net.exe, nltest.exe) spawned by RMM agents.
