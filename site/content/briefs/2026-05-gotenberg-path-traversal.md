---
title: Gotenberg Path Traversal Vulnerability via Windows-Style Separators in Zip Entry Name (CVE-2026-44829)
slug: 2026-05-gotenberg-path-traversal
description: Gotenberg is vulnerable to path traversal (CVE-2026-44829) due to improper sanitization of filenames in zip archives, allowing attackers to write files outside the intended extraction directory by using Windows-style path separators (backslashes) in uploaded filenames, affecting versions up to 8.32.0.
date: "2026-05-29T16:38:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - zip-archive
  - cve-2026-44829
vendors:
  - GitHub
products:
  - gotenberg/gotenberg
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-hwc4-gmrw-5222
rules:
  - title: Detects CVE-2026-44829 Exploitation - Gotenberg Path Traversal Attempt via Filename
    description: Detects CVE-2026-44829 exploitation - HTTP POST requests to Gotenberg endpoints containing filenames with Windows-style path separators (backslashes).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-44829 Exploitation - Gotenberg Path Traversal Archive Extraction
    description: Detects CVE-2026-44829 exploitation - monitors process creation for archive extraction tools extracting files with path traversal sequences.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A path traversal vulnerability exists in Gotenberg versions up to 8.32.0. The vulnerability stems from the `filepath.Base` function on the Linux container not stripping backslashes (`\`) from filenames, as it's only a path separator on Windows. By crafting a multipart filename like `..\..\..\..\Windows\System32\evil.pdf`, an attacker can bypass Gotenberg's input sanitization. This filename is then used verbatim as the zip entry name when a multi-output route (e.g., `/forms/pdfengines/split`) returns its result as a zip. Windows zip extractors interpret backslashes as path separators, leading to files being written outside the intended extraction directory. This issue is tracked as CVE-2026-44829.

## Attack Chain

1. An attacker crafts a malicious PDF file with embedded payload, such as shell script.
2. The attacker sends a POST request to a Gotenberg multi-output route (e.g., `/forms/pdfengines/split`) with a multipart filename containing Windows-style path separators (backslashes), such as `..\\..\\..\\..\\Windows\\System32\\evil.pdf`.
3. Gotenberg's `filepath.Base` function fails to properly sanitize the filename due to the use of backslashes, which are not recognized as path separators on Linux.
4. The unsanitized filename is then passed to `ctx.diskToOriginal` and subsequently used by `SplitPdfStub` to construct the zip entry name.
5. The `archives.FilesFromDisk` and `archives.Zip{}.Archive` functions are used to create a zip archive containing the malicious filename.
6. A Windows-based client extracts the generated zip archive, interpreting the backslashes as path separators.
7. The malicious PDF file is written to an arbitrary location outside the intended extraction directory, such as `C:\Windows\System32\evil.pdf`.
8. The attacker gains arbitrary file write capabilities on the target system, leading to potential code execution.

## Impact

Successful exploitation of this vulnerability (CVE-2026-44829) allows attackers to write arbitrary files on a Windows system that extracts the ZIP archive created by Gotenberg. This can lead to arbitrary code execution if the attacker can overwrite critical system files or place executable files in startup directories. The vulnerability affects all multi-output Gotenberg routes, including `/forms/pdfengines/split`, `/forms/pdfengines/flatten`, `/forms/pdfengines/convert`, and others, expanding the attack surface.

## Recommendation

*   Apply the suggested patch provided in the advisory (https://github.com/advisories/GHSA-hwc4-gmrw-5222) to sanitize filenames and prevent path traversal attacks.
*   Deploy the Sigma rules below to detect exploitation attempts targeting CVE-2026-44829 by monitoring HTTP requests to Gotenberg endpoints with suspicious filenames.
*   Monitor web server logs for HTTP POST requests to Gotenberg endpoints (e.g., `/forms/pdfengines/split`) containing filenames with Windows-style path separators (backslashes) to detect potential exploitation attempts.
