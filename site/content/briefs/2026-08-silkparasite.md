---
title: SilkParasite Espionage Campaign Targeting Central Asian Governments
slug: 2026-08-silkparasite
description: The SilkParasite threat actor is targeting Central Asian government entities with a modular suite of seven remote access tools delivered via spear-phishing and DLL sideloading.
date: "2026-08-19T14:32:40Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - SilkParasite
vendors:
  - Microsoft
products:
  - Office
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attack chains begin with password-protected RAR archives bearing malicious Microsoft Office documents that are likely delivered via spear-phishing emails.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: 'The most consistent detection surface across the campaign is DLL sideloading, and the reliable signal is the pairing, not the DLL name alone: a legitimately signed application loading a library placed beside it while running from an unusual location.'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: DriveSilkRAT, which uses Google Drive as command-and-control (C2) to poll a specific folder for tasking.
    confidence_band: high
rules:
  - title: Detect DLL Sideloading via Signed Binary
    description: Detects DLL sideloading by monitoring for legitimate signed binaries that load libraries from unusual or user-writable locations
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1574.002
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy DLL sideloading detection rule to SIEM
      owner: Detection Engineering
      due: 24h
      evidence: Source notes DLL sideloading as the most consistent detection surface.
  hunt_leads:
    - lead: Search for Office processes spawning suspicious binaries in non-standard paths
      technique_id: T1574.002
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Macro initiates DLL sideloading sequence to drop payload.
  mitigation_plan:
    - priority: medium_term
      action: Restrict macro execution in Office environments
      owner: IT Operations
      addresses: Phishing-based initial access
      evidence: Campaign uses malicious macros.
---

SilkParasite is an espionage-focused threat cluster assessed with medium confidence to have a China-nexus. The campaign has been active since late 2025, specifically targeting government organizations in Uzbekistan, Turkmenistan, Kyrgyzstan, Tajikistan, and Kazakhstan. The threat group employs a diverse arsenal of seven distinct RAT families, five of which were newly documented: DriveSilkRAT, CookiETagRAT, NomadRAT, GoginRAT, and NodeEdgeRAT. These tools are built in .NET, C++, Go, and JavaScript, and leverage a modular, plugin-oriented architecture to maintain a low footprint. The operators utilize DLL sideloading to execute malicious payloads, often bringing their own signed binaries to facilitate evasion. The campaign shows potential signs of AI-assisted development, specifically in codebase architecture and test function generation.

## Attack Chain

1. Initial access via spear-phishing emails containing password-protected RAR archives.
2. The RAR archives contain malicious Microsoft Office documents with embedded VBA macros.
3. The VBA macro checks for the presence of Kaspersky antivirus to determine if the environment is suitable for infection.
4. The macro executes a DLL sideloading sequence, dropping a rogue DLL beside a legitimately signed binary.
5. The legitimately signed binary loads the malicious DLL to initiate the first-stage payload execution.
6. Implants (such as DriveSilkRAT, GoginRAT, or NomadRAT) establish C2 via cloud services (e.g., Google Drive) or custom HTTP header tagging.
7. Modular plugins are fetched and executed in memory for system enumeration, file exfiltration, and command execution.

## Impact

The campaign has resulted in at least 65 confirmed infections, primarily affecting government entities across Central Asia. Successful exploitation allows for persistent unauthorized access to sensitive government networks, host enumeration, and data exfiltration. The use of modular plugin architecture allows the attackers to continuously adapt to the victim's environment, making the threat highly persistent and difficult to eradicate.

## Recommendation

- Implement behavioral monitoring to detect DLL sideloading by alerting on signed binaries loading modules from non-standard or user-writable directories.
- Deploy the Sigma rule provided below to detect suspicious DLL sideloading attempts in your environment.
- Block or monitor traffic to public cloud storage services (like Google Drive) when initiated by unsigned or suspicious processes originating from unusual host paths.
- Conduct threat hunting for the execution of Office macros that perform environment checks for security software, specifically looking for process-creation events linked to Microsoft Office applications.
