---
title: 'Bad Apples: Weaponizing Native macOS Primitives for Lateral Movement and Execution'
slug: 2026-04-bad-apples-macos-lotl
description: Adversaries are increasingly targeting macOS environments, leveraging native tools like Remote Application Scripting (RAS) and Spotlight metadata to bypass security controls for remote code execution and lateral movement.
date: "2026-04-21T10:01:16Z"
severities:
  - high
tags:
  - macos
  - lotl
  - lateral-movement
  - execution
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1072
    technique_name: Software Deployment Tools
references:
  - https://blog.talosintelligence.com/bad-apples-weaponizing-native-macos-primitives-for-movement-and-execution/
rules:
  - title: Detect Remote Apple Event Lateral Movement
    description: Detects the execution of osascript with the eppc:// URI scheme, which indicates Remote Apple Event-based lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.005
    data_sources:
      - process_creation
      - macos
  - title: Detect Terminal.app as Execution Proxy
    description: Detects Terminal.app executing bash with Base64 decoding commands, which indicates a potential RAS-based remote execution attempt using Terminal.app as an execution proxy.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1072
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

With macOS adoption growing in enterprise environments, particularly among developers and DevOps teams, it has become an attractive target for malicious actors. This report highlights the under-documented "living-off-the-land" (LOTL) techniques specific to macOS. Attackers are exploiting native features like Remote Application Scripting (RAS) to achieve remote execution and are abusing Spotlight metadata (Finder comments) for payload staging, evading traditional static file analysis…
