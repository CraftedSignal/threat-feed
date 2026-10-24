---
brief_id: brief-2026-10-24-popcorn-time-updater
event_id: brief-2026-10-24-popcorn-time-updater
revision: 1
activity_at: "2026-10-24T11:13:30Z"
title: 'Time4Popcorn: Insecure automatic updater vulnerability (CVE-2026-30612)'
slug: 2026-10-popcorn-time-updater
description: A critical vulnerability (CVE-2026-30612) in the abandoned Time4Popcorn application allows remote attackers to hijack the unauthenticated background updater to execute arbitrary code with SYSTEM or root privileges.
date: "2026-10-24T11:13:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
tags:
  - endpoint-security
  - vulnerability
  - remote-code-execution
  - botnet
products:
  - Time4Popcorn (Windows <= 6.2.1.18, Mac <= 6.2.1.17, Android <= 3.5.0.173)
affected_os:
  - Windows
  - macOS
  - Android
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: The updater ran in the background on Windows and Mac from the moment the computer started.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    subtechnique_id: T1547.001
    subtechnique_name: Registry Run Keys / Startup Folder
    evidence: The updater ran in the background on Windows and Mac from the moment the computer started.
    confidence_band: high
cves:
  - id: CVE-2026-30612
    cvss: 9.8
    epss: 0.00416
    kev_status: "false"
references:
  - https://thehackernews.com/2026/10/researchers-push-over-2-million-updates.html
iocs:
  - type: domain
    value: popcorntimeupd.xyz
ioc_counts:
  domain: 1
rules:
  - title: Detect Time4Popcorn Updater Execution
    description: Detects the execution of the vulnerable Time4Popcorn updater process.
    platform: sigma
    severity: high
    tactics:
      - execution
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
    - IT Operations
  immediate_actions:
    - action: Inventory enterprise assets for Time4Popcorn application
      owner: SOC
      due: 24h
      evidence: CVE-2026-30612 affects Time4Popcorn installations
  hunt_leads:
    - lead: Search endpoint telemetry for persistence mechanisms associated with Time4Popcorn (PT.updd.plist on macOS, registry keys for Updater.exe on Windows)
      technique_id: T1547.001
      data_needed:
        - Endpoint file and registry audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Updater runs at startup to check for new versions
  mitigation_plan:
    - priority: immediate
      action: Uninstall Time4Popcorn globally
      owner: IT Operations
      addresses: CVE-2026-30612
      evidence: Eye's advice is to uninstall Popcorn Time.
---

The Time4Popcorn application, an abandoned fork of Popcorn Time, contains a critical vulnerability (CVE-2026-30612) in its background updater component. The updater fetches and installs updates over an unencrypted connection without performing any integrity checks or identity verification. An attacker who registers domains formerly used by the application can serve malicious payloads to all connected clients, resulting in full system compromise. The vulnerability affects Windows (up to 6.2.1.18), macOS (up to 6.2.1.17), and Android (up to 3.5.0.173) versions.

## Impact

The vulnerability allows an unauthenticated attacker to achieve remote code execution at the highest privilege level (SYSTEM or root). Potential impacts include ransomware deployment, credential theft, and forced recruitment into botnets. While no active exploitation by malicious actors was confirmed by the researchers as of October 2026, the potential for widespread automated compromise is high.

## Recommendation

- Immediately uninstall Time4Popcorn from all corporate and personal devices.
- If immediate removal is not possible, disable the updater service manually:
 - Windows: Execute `sc.exe stop "Update service"` and `sc.exe config "Update service" start= disabled`.
 - macOS: Execute `launchctl unload -w /Library/LaunchDaemons/PT.updd.plist`.
- Use endpoint detection telemetry to identify the presence of `Updater.exe` (Windows) or `PT.updd` (macOS) and correlate with network logs.
