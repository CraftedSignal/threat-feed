---
title: MCPHub Path Traversal Vulnerability via Malicious MCPB Manifest Name
slug: 2024-01-mcphub-path-traversal
description: MCPHub is vulnerable to path traversal, where a malicious MCPB file with a crafted manifest.name can cause files to be extracted to arbitrary locations due to missing sanitization in the upload handler.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
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

MCPHub is vulnerable to a path traversal vulnerability affecting versions prior to 0.12.13. The vulnerability exists in the MCPB file upload handler, which extracts a ZIP file and reads the `manifest.json` file. The `name` field from the manifest is directly concatenated into the file path without any sanitization or path traversal character validation. This allows an attacker to craft a malicious MCPB file with a `manifest.name` containing directory traversal sequences (e.g., `../../../etc/malicious`), leading to arbitrary file extraction and potential directory deletion via the `cleanupOldMcpbServer` function. This vulnerability poses a significant risk to systems running vulnerable versions of MCPHub, potentially allowing attackers to overwrite critical system files or execute arbitrary code.

## Attack Chain

1. An attacker crafts a malicious MCPB file.
2. The malicious MCPB file contains a `manifest.json` file with a `name` field set to a path traversal string (e.g., `../../../tmp/evil`).
3. The attacker uploads the malicious MCPB file to the `/mcpb/upload` endpoint.
4. The `uploadMcpbFile` function extracts the uploaded MCPB file to a temporary directory.
5. The function reads and parses the `manifest.json` file from the temporary directory.
6. The `manifest.name` value (containing the path traversal string) is used to construct the final extraction directory path using `path.join`.
7. The server attempts to create the directory specified by the crafted path and moves the extracted files to this location. Due to the path traversal, the files are written outside the intended directory.
8. The `cleanupOldMcpbServer` function may be triggered, attempting to delete directories based on the unsanitized name, though constrained to the upload directory.

## Impact

Successful exploitation of this path traversal vulnerability allows an attacker to write files to arbitrary locations on the server's file system. This could lead to overwriting critical system files, injecting malicious code into existing applications, or gaining unauthorized access to sensitive data. The exact impact depends on the permissions of the user running the MCPHub application and the contents of the files being written. If the attacker can overwrite executable files or configuration files, they could achieve arbitrary code execution and full system compromise.

## Recommendation

*   Apply the remediation recommendations from the original advisory: Use `path.basename()` to strip directory components from `manifest.name`, and enforce a strict character whitelist before use.
*   Deploy the Sigma rule "Detect MCPHub Path Traversal Attempt via Manifest Name" to identify attempts to exploit this vulnerability by monitoring for specific path traversal sequences in the manifest name (see Sigma rule).
*   Upgrade MCPHub to version 0.12.13 or later to patch this vulnerability.
