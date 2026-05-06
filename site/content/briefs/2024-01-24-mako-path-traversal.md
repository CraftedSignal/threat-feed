---
title: Mako Template Engine Path Traversal Vulnerability on Windows
slug: 2024-01-24-mako-path-traversal
description: A path traversal vulnerability exists in Mako versions 1.3.11 and earlier on Windows, allowing attackers to read arbitrary files outside the configured template directory by using backslashes in URIs to bypass directory traversal checks.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - windows
vendors:
  - pip
products:
  - Mako (<= 1.3.11)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-2h4p-vjrc-8xpq
rules:
  - title: Detect Mako Template Path Traversal Attempt via Backslash
    description: Detects attempts to exploit the Mako template path traversal vulnerability (CVE-2026-44307) by identifying requests containing backslash-based path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-44307
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Mako Template Execution with Suspicious Characters in URI
    description: Detects potential Mako template execution when suspicious characters are present in the URI, indicating possible path traversal attempts.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-44307
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Mako is a template library written in Python. A path traversal vulnerability, identified as CVE-2026-44307, affects Mako versions 1.3.11 and earlier when running on Windows. The vulnerability stems from inconsistencies in how Mako handles path normalization. Specifically, the `TemplateLookup.get_template()` function, which uses `posixpath` for URI normalization, differs from the `Template.__init__()` function, which uses `os.path` for file access and validation. This discrepancy allows attackers to bypass directory traversal checks by crafting URIs that contain backslashes. Backslashes are treated as path separators by `os.path` on Windows but as literal characters by `posixpath`, leading to incorrect validation. This vulnerability allows an attacker to load and disclose readable files outside the configured template directory if an application passes user-controlled template names or include paths to `TemplateLookup.get_template()`.

## Attack Chain

1. The attacker crafts a malicious URI containing backslash-based path traversal sequences (e.g., `\..\..\secret.txt`).
2. The application passes the crafted URI to `TemplateLookup.get_template()`.
3. `get_template()` strips leading forward slashes and normalizes the URI using `posixpath.normpath()`. Backslashes are treated as literal characters, bypassing directory traversal checks.
4. The URI is passed to `Template.__init__()` for template initialization and validation.
5. `Template.__init__()` uses `os.path.normpath()` to normalize the URI. On Windows, this resolves backslash traversal, converting `\..\..\secret.txt` to `\secret.txt`.
6. The `startswith("..")` check in `Template.__init__()` incorrectly passes because the normalized path `\secret.txt` does not begin with `..`.
7. `os.path.isfile()` is used to check for the existence of the file. On Windows, `os.path.isfile()` interprets backslashes as path separators, successfully resolving the path and locating the file outside the intended template directory.
8. The attacker successfully reads the contents of the file, leading to information disclosure.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files on the system that the application has access to. The vulnerability affects Mako versions 1.3.11 and earlier on Windows. If the targeted file contains Mako/Python template syntax, it may also be parsed and executed as a template, potentially leading to further code execution. The primary impact is local file disclosure.

## Recommendation

*   Apply the patch or upgrade to a version of Mako greater than 1.3.11 to remediate CVE-2026-44307.
*   Sanitize user-supplied template names and include paths before passing them to `TemplateLookup.get_template()` to prevent path traversal attacks.
*   Deploy the Sigma rules in this brief to your SIEM to detect exploitation attempts targeting this vulnerability.
