---
title: Arbitrary File Write in CLI Bridge via Dangling Symlink Traversal
slug: 2026-10-cli-bridge-path-traversal
description: CLI Bridge versions prior to 0.0.2 are vulnerable to path traversal through improper symlink resolution, potentially allowing arbitrary file writes outside the intended workspace root.
date: "2026-10-19T18:09:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cli_bridge:cli_bridge:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - arbitrary-file-write
  - cve
vendors:
  - CLI Bridge
products:
  - CLI Bridge (< 0.0.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The fallback resolves only the parent directory and returns the symlink path as safe, so write_file follows the link and can write arbitrary files outside the workspace root.
    confidence_band: high
cves:
  - id: CVE-2026-111045
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111045
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade CLI Bridge to 0.0.2 or later
      owner: IT Operations
      addresses: CVE-2026-111045
      evidence: This issue is fixed in version 0.0.2.
---

CLI Bridge contains a critical path traversal vulnerability (CVE-2026-111045) that impacts filesystem security within the workspace root. The issue arises in the `resolveSafePath` function, which fails to properly validate paths when encountering a dangling symlink (a symlink pointing to a nonexistent target). Specifically, when `fs.realpathSync` throws an `ENOENT` exception, the logic incorrectly falls back to resolving only the parent directory and marks the symlink path as safe. Because the `write_file` operation subsequently follows these symlinks, an attacker can manipulate symlinks to write files to arbitrary locations outside the defined workspace boundary. This vulnerability is addressed in version 0.0.2.

## Impact

Successful exploitation allows an attacker to bypass workspace isolation, leading to arbitrary file write operations. This can be leveraged to overwrite critical system configuration files, inject malicious code into application directories, or gain unauthorized persistent access to the underlying host system, depending on the permissions of the process running CLI Bridge.

## Recommendation

* Update CLI Bridge to version 0.0.2 or later immediately to incorporate the patch for CVE-2026-111045.
* Audit filesystem access logs to identify attempts to write files outside of designated workspace directories.
* Monitor for the creation of symbolic links within workspace environments that point to sensitive system directories or files.
