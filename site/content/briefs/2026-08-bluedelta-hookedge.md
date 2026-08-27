---
title: BlueDelta Targets European Defense and Diplomacy with HOOKEDGE Backdoor
slug: 2026-08-bluedelta-hookedge
description: The Russian threat group BlueDelta is using a custom batch-script backdoor named HOOKEDGE to target European government and diplomatic entities via macro-enabled Microsoft Word documents that leverage legitimate webhook services for C2.
date: "2026-08-27T15:11:02Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - BlueDelta
tags:
  - espionage
  - windows
  - phishing
  - c2
vendors:
  - Microsoft
products:
  - Word
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: The campaigns delivered a lightweight Windows batch-script backdoor, dubbed HOOKEDGE, via macro-enabled Microsoft Word documents.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: HOOKEDGE, a lightweight batch-script backdoor.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102.001
    technique_name: 'Web Service: Dead Drop Resolver'
    evidence: HOOKEDGE shares HEADLACE's core architecture, abusing legitimate webhook services for command-and-control (C2), payload staging, and data exfiltration.
    confidence_band: high
references:
  - https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge
iocs:
  - type: domain
    value: webhook.site
ioc_counts:
  domain: 1
rules:
  - title: Detect Office Applications Spawning Suspicious Child Processes
    description: Detects Microsoft Word or Excel spawning cmd.exe or powershell.exe, which is a common indicator of macro-based payload delivery.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

BlueDelta, a Russian state-sponsored threat group also known as APT28, Fancy Bear, and Forest Blizzard, has been conducting a persistent espionage campaign against defense and diplomatic organizations in Romania, Spain, and Türkiye. Operational between September 2025 and April 2026, the campaign utilizes a lightweight, modular backdoor dubbed HOOKEDGE. This malware is a refined successor to the HEADLACE backdoor and is delivered via spearphishing campaigns using macro-enabled Microsoft Word documents. 

The HOOKEDGE implant is primarily composed of Windows batch scripts designed to execute commands and exfiltrate data by abusing legitimate internet services, specifically 'webhook[.]site'. This technique allows the group to blend malicious command-and-control (C2) traffic with normal network operations while maintaining a low footprint. The group has demonstrated significant tradecraft refinement during this period, including tailoring beaconing intervals based on target intelligence value to avoid detection and optimizing code to bypass sandbox environments. The use of diplomatic lures, including content impersonating the Spanish government, highlights the group's focus on intelligence collection aligned with Russian state interests.

## Attack Chain

1. Initial access is established through spearphishing emails containing macro-enabled Microsoft Word documents.
2. The user is prompted to enable content, triggering the execution of an embedded malicious VBA macro.
3. The VBA macro drops and executes a Windows batch script (the HOOKEDGE backdoor) on the target host.
4. The HOOKEDGE backdoor initiates persistence mechanisms, typically via the creation of malicious scheduled tasks.
5. The backdoor performs environmental reconnaissance and determines its beaconing interval for the current session.
6. HOOKEDGE establishes C2 communication by sending HTTP requests to 'webhook[.]site' to retrieve follow-on commands or additional payloads.
7. The malware executes secondary payloads or commands, potentially invoking headless Microsoft Edge instances to further interact with the environment.
8. Stolen data is exfiltrated back through the same webhook infrastructure to conclude the collection mission.

## Impact

The campaign targets sensitive government and diplomatic communications, potentially resulting in the compromise of classified policy documents, strategic meeting agendas, and regional intelligence related to European parliamentary elections. Observed victims include personnel in Romania, Spain, and Türkiye. Successful exploitation provides the adversary with persistent, low-profile access for ongoing espionage, enabling the exfiltration of high-value intelligence over extended periods.

## Recommendation

* Implement Group Policy or Intune settings to block all macros in Office documents originating from the internet; this disrupts the primary delivery vector of HOOKEDGE.
* Enable Sysmon event ID 1 (Process Creation) and monitor for cmd.exe or powershell.exe spawned by WinWord.exe or Excel.exe.
* Monitor for the creation of new scheduled tasks using 'schtasks.exe' or 'powershell.exe' immediately following the execution of Office applications.
* Deploy network-level detection to flag outbound HTTP requests to known public webhook relay services like 'webhook[.]site'.
* Monitor for suspicious headless execution of Microsoft Edge ('msedge.exe') from non-interactive or service-related accounts.
