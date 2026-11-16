---
brief_id: brief-2026-11-16-coffeeloader-retadup
event_id: brief-2026-11-16-coffeeloader-retadup
revision: 1
activity_at: "2026-11-16T10:20:36Z"
title: CoffeeLoader and Retadup Worm Revived with OpenGL Armoury Packer
slug: 2026-11-coffeeloader-retadup
description: CoffeeLoader is being distributed via revived Retadup worm infrastructure, featuring a new Armoury packer variant that utilizes OpenGL for shellcode decryption.
date: "2026-11-16T10:20:36Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://securelist.com/retadup-delivers-coffeeloader/121908/
  observed_at: "2026-11-16T10:20:36Z"
  confidence: medium
source_assessment:
  reliability: A
  credibility: "1"
  likelihood: likely
tags:
  - malware
  - downloader
  - trojan
  - worm
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    subtechnique_id: T1547.001
    subtechnique_name: Registry Run Keys / Startup Folder
    evidence: The Run registry key is used for autorun.
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
    subtechnique_id: T1055.001
    subtechnique_name: Dynamic-link Library Injection
    evidence: The second is a stager that creates a new dllhost.exe process and injects the main body of CoffeeLoader into it
references:
  - https://securelist.com/retadup-delivers-coffeeloader/121908/
iocs:
  - type: domain
    value: internet-speed-check.com
  - type: domain
    value: alphanoob.com
  - type: domain
    value: newblackage.com
ioc_counts:
  domain: 3
rules:
  - title: Detect CoffeeLoader Persistence via Registry Run Key
    description: Detects the establishment of persistence by CoffeeLoader using registry run keys with a specific naming convention of eight hexadecimal digits.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

## Overview
In August 2026, researchers observed a new variant of the CoffeeLoader malware delivered by the revived Retadup worm. While the original Retadup botnet was neutralized by law enforcement in 2019, third-party actors began re-registering its decommissioned C2 domains around 2024 to deliver secondary payloads, including CoffeeLoader. The new infection chain uses a patched 7-Zip library (7z.dll) as a dropper and a redesigned Armoury packer that utilizes the OpenGL library for shellcode decryption.

## Attack Chain
1. Initial access is established via Retadup worm propagation on infected USB flash drives, where the worm spreads as hidden files and shortcuts (LNK).
2. The Retadup worm communicates with re-registered C2 domains to download secondary payloads, such as the CoffeeLoader NSIS-based installer.
3. The installer drops a malicious 7z.dll into a temporary directory and executes it via rundll32.exe.
4. The Armoury packer decrypts the CoffeeLoader downloader using OpenGL.
5. The CoffeeLoader downloader establishes persistence in %PROGRAMDATA% or %LOCALAPPDATA% and adds a run key to the Windows Registry using names derived from system volume information.
6. The downloader prevents the user from disabling autorun through Task Manager by modifying the StartupApproved registry key.
7. The malware injects the CoffeeLoader main body into system processes (e.g., dllhost.exe, WerFault.exe) and retrieves the main Trojan body via HTTPS from a hardcoded C2.

## Impact
Successful infection grants attackers the ability to run payloads received from the C2, including injecting code into processes, executing files from disk, or running DLLs via rundll32.exe.

## Recommendation
- Monitor registry modifications for Run keys using eight-character hexadecimal filenames.
- Monitor for rundll32.exe executions originating from %PROGRAMDATA% or %LOCALAPPDATA%.
- Monitor for process injection into system processes such as dllhost.exe, WerFault.exe, svchost.exe, OpenWith.exe, or AtBroker.exe.
