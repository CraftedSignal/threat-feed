---
title: GhostLoader Malware Targeting macOS via GitHub and AI Workflows
slug: 2024-01-ghostloader
description: GhostLoader malware leverages GitHub repositories and AI-assisted development workflows to distribute credential-stealing payloads targeting macOS systems.
date: "2026-03-21T13:03:03Z"
severities:
  - high
tags:
  - github
  - malware
  - macos
  - credential-theft
  - ai
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rzqxl0/ghostloader_malware_github_repositories_ai/
  - https://www.jamf.com/blog/ghostclaw-ghostloader-malware-github-repositories-ai-workflows/
rules:
  - title: Detect Execution of Suspicious Binaries from User Directories on macOS
    description: Detects the execution of unusual or unsigned binaries within user directories on macOS, which may indicate the presence of GhostLoader or similar malware.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - macos
  - title: Detect Outbound Network Connections from Newly Executed Processes on macOS
    description: Detects outbound network connections initiated by processes that have been recently executed, potentially indicating command and control or data exfiltration activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - macos
rules_count: 2
---

GhostLoader is a malware campaign observed using GitHub repositories and AI-assisted development workflows to deliver malicious payloads specifically designed to steal credentials from macOS systems. The threat leverages the trust associated with software repositories and the increasing adoption of AI tools in development to potentially bypass security measures. While the exact start date of the campaign is not specified, the report from Jamf highlights its recent emergence as a notable threat…
