---
title: Gotenberg ExifTool Argument Injection via Metadata Values
slug: 2024-01-02-gotenberg-exiftool-injection
description: Gotenberg version 8.30.1 and earlier is vulnerable to argument injection, where an unauthenticated attacker can inject arbitrary ExifTool pseudo-tags via newline characters in metadata values, leading to arbitrary file manipulation within the container filesystem.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - argument-injection
  - vulnerability
  - container
vendors:
  - Gotenberg
products:
  - Gotenberg <= 8.30.1
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-q7r4-hc83-hf2q
rules:
  - title: Detect Gotenberg ExifTool Metadata Injection Attempt
    description: Detects attempts to inject ExifTool arguments via newline characters in metadata values in Gotenberg's `/forms/pdfengines/metadata/write` endpoint.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Creation within Gotenberg Container
    description: Detects the creation of files or symbolic links in unusual locations within a Gotenberg container, potentially indicating exploitation of the ExifTool injection vulnerability.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Gotenberg, a Docker-based solution for converting various document formats to PDF, is vulnerable to an argument injection flaw affecting versions 8.30.1 and earlier. This vulnerability stems from insufficient sanitization of metadata values passed to the ExifTool during PDF processing. Specifically, the application fails to properly sanitize newline characters within metadata values. By exploiting this flaw, an unauthenticated attacker can inject arbitrary ExifTool pseudo-tags, such as `-FileName`, `-Directory`, `-SymLink`, and `-HardLink`, allowing for unauthorized file manipulation, including renaming, moving, overwriting, and creating symbolic or hard links to files within the container's filesystem. The vulnerability is a bypass of an incomplete key sanitization fix introduced in version 8.30.1, highlighting the importance of thorough input validation.

## Attack Chain

1. An attacker crafts a malicious PDF file or uses an existing PDF.
2. The attacker injects a newline character followed by an ExifTool pseudo-tag (e.g., `-FileName=/tmp/inject_proof`) into a metadata value (e.g., the 'Title' field).
3. The attacker sends the PDF, along with the crafted metadata, to the Gotenberg `/forms/pdfengines/metadata/write` endpoint via a POST request.
4. Gotenberg's `WriteMetadata` function in `pkg/modules/exiftool/exiftool.go` processes the metadata.
5. The unsanitized metadata value is passed to `go-exiftool`'s `SetString` function.
6. `go-exiftool` writes the key-value pair to ExifTool's stdin using `fmt.Fprintln(e.stdin, "-"+k+"="+str)`.
7. The newline character splits the ExifTool stdin line into two separate arguments, injecting the attacker's pseudo-tag.
8. ExifTool executes the injected command (e.g., moving the PDF to `/tmp/inject_proof`).

## Impact

Successful exploitation allows an unauthenticated attacker to rename or move any PDF being processed to an arbitrary path within the container filesystem, which runs as root by default. This also enables overwriting arbitrary files (e.g., corrupting the `/etc/passwd` file), creating symlinks, and creating hard links. The container filesystem becomes fully exposed to arbitrary file manipulation.

## Recommendation

*   Apply value sanitization parallel to the existing key check in `WriteMetadata` as described in the advisory.
*   Implement detection rules to identify attempts to exploit the vulnerability by monitoring for suspicious characters in HTTP requests to the `/forms/pdfengines/metadata/write` endpoint using the provided Sigma rule.
*   Monitor for unexpected file modifications within the Gotenberg container, especially the creation or modification of symbolic links and hard links, using `file_event` log source.
*   Upgrade to a patched version of Gotenberg that addresses this vulnerability to prevent exploitation (CVE-2026-40281).
