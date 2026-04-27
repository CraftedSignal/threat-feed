---
title: MCPHub Path Traversal Vulnerability via Malicious MCPB Manifest Name
slug: 2024-01-mcphub-path-traversal
description: MCPHub is vulnerable to path traversal, where a malicious MCPB file with a crafted manifest.name can cause files to be extracted to arbitrary locations due to missing sanitization in the upload handler.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - path-traversal
  - web-application
  - mcphub
vendors:
  - samanhappy
products:
  - '@samanhappy/mcphub ( < 0.12.13)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-p3h2-2j4p-p83g
rules:
  - title: Detect MCPHub Path Traversal Attempt via Manifest Name
    description: Detects path traversal attempts in MCPHub by monitoring for specific sequences in the manifest name during file uploads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect MCPHub Manifest Name with Suspicious Characters
    description: Detects MCPHub manifest uploads with potentially malicious characters in the manifest name, indicating a possible path traversal attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

MCPHub is vulnerable to a path traversal vulnerability affecting versions prior to 0.12.13. The vulnerability exists in the MCPB file upload handler, which extracts a ZIP file and reads the `manifest.json` file. The `name` field from the manifest is directly concatenated into the file path without any sanitization or path traversal character validation. This allows an attacker to craft a malicious MCPB file with a `manifest.name` containing directory traversal sequences (e.g…
