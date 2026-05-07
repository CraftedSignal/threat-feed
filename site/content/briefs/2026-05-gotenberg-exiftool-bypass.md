---
title: Gotenberg ExifTool Metadata Write Blocklist Bypass Vulnerability
slug: 2026-05-gotenberg-exiftool-bypass
description: The ExifTool metadata write blocklist in Gotenberg v8 can be bypassed using ExifTool's group-prefix syntax, enabling arbitrary file rename, move, hardlink, and symlink creation on the server.
date: "2026-05-07T00:55:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - gotenberg
  - exiftool
  - metadata
  - file-manipulation
vendors:
  - Gotenberg
products:
  - Gotenberg (<= 8.29.1)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-7v3r-m9c8-r855
rules:
  - title: Detect Gotenberg ExifTool Metadata Write - File Rename
    description: Detects attempts to rename files via the Gotenberg ExifTool metadata write endpoint using the File:FileName parameter.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect Gotenberg ExifTool Metadata Write - Symlink Creation
    description: Detects attempts to create symlinks via the Gotenberg ExifTool metadata write endpoint using the File:SymLink parameter.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Gotenberg, a Docker-powered document conversion API, is vulnerable to a bypass in its ExifTool metadata write blocklist. This vulnerability, affecting Gotenberg v8 (<= 8.29.1), allows unauthenticated attackers to manipulate file system operations within the Gotenberg container. The vulnerability leverages ExifTool's group-prefix syntax to circumvent the intended restrictions on pseudo-tags like `FileName`, `Directory`, `HardLink`, and `SymLink`. This bypass is particularly critical as it directly negates the fix implemented for GHSA-qmwh-9m9c-h36m. The pre-auth nature of this vulnerability significantly broadens the attack surface, allowing malicious actors to potentially gain unauthorized access and control over file system resources.

## Attack Chain

1. The attacker sends a crafted HTTP request to the `/forms/pdfengines/metadata/write` endpoint.
2. The request includes a `metadata` field containing a JSON object with malicious ExifTool tags.
3. The attacker uses the group-prefix syntax (e.g., `File:FileName`) to bypass the tag blocklist in `pkg/modules/exiftool/exiftool.go`.
4. The `safeKeyPattern` regex (`^[a-zA-Z0-9\-_.:]+$`) allows colons, so prefixed tag names pass validation.
5. The `SetNewValue` function in ExifTool's `Writer.pl` strips the prefix, allowing the malicious tag to be processed.
6. ExifTool executes the file system operation specified by the malicious tag (e.g., renaming, moving, creating symlinks).
7. If the Gotenberg deployment uses mounted volumes or is non-containerized, the attacker can perform actions outside the container.
8. The attacker achieves arbitrary file read via symlink chaining and file overwrite via directory manipulation.

## Impact

The vulnerability allows pre-authenticated attackers to rename, move, or create links to files within the Gotenberg container. In deployments with mounted volumes or non-containerized setups, this can lead to arbitrary file read and overwrite via symlink chaining and directory manipulation. The vulnerability impacts Gotenberg v8 (<= 8.29.1) and can potentially compromise the confidentiality and integrity of data processed by the service. This is a direct bypass of a previous security fix, increasing the risk of exploitation.

## Recommendation

*   Upgrade Gotenberg to a version greater than 8.29.1 to remediate CVE-2026-42590.
*   Implement input validation and sanitization on the `metadata` field of the `/forms/pdfengines/metadata/write` endpoint to prevent exploitation of the ExifTool group-prefix bypass.
*   Deploy the Sigma rule `Detect Gotenberg ExifTool Metadata Write - File Rename` to detect attempts to rename files using the vulnerable endpoint.
*   Monitor web server logs for requests to `/forms/pdfengines/metadata/write` with `metadata` containing "File:FileName", "File:Directory", "File:HardLink", or "File:SymLink" to detect potential exploitation attempts.
