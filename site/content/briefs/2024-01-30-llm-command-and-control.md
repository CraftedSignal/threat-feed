---
title: Suspicious Processes Connecting to Large Language Model Endpoints
slug: 2024-01-30-llm-command-and-control
description: This rule detects DNS queries to known Large Language Model (LLM) domains by unsigned binaries or common Windows scripting utilities, indicating potential command and control activity leveraging LLMs for dynamic actions on compromised systems.
date: "2026-04-22T16:34:10Z"
severities:
  - medium
tags:
  - command_and_control
  - malware
  - llm
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/py.lamehug
  - https://attack.mitre.org/techniques/T1102/
  - https://attack.mitre.org/techniques/T1102/002/
  - https://attack.mitre.org/tactics/TA0011/
rules:
  - title: Suspicious Process DNS Query to LLM API Endpoint
    description: Detects suspicious processes making DNS queries to LLM API endpoints.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1102
    data_sources:
      - dns_query
      - windows
  - title: Scripting Utility Querying LLM API Endpoint
    description: Detects scripting utilities making DNS queries to LLM API endpoints.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1102
    data_sources:
      - dns_query
      - windows
  - title: macOS process DNS query LLM API Endpoint
    description: Detects processes on macOS making DNS queries to LLM API endpoints.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1102
    data_sources:
      - dns_query
      - macos
rules_count: 3
---

This detection identifies instances where suspicious processes are communicating with known Large Language Model (LLM) endpoints. The activity suggests potential command and control behavior, where malware or unauthorized scripts leverage LLMs to dynamically execute actions on compromised systems. This behavior emerged in late 2025 and continues to evolve. The rule focuses on detecting DNS queries originating from unsigned binaries or common scripting utilities like PowerShell, `mshta.exe`, and…
