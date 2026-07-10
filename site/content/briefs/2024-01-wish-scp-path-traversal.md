---
title: charm.land/wish SCP Path Traversal Vulnerability
slug: 2024-01-wish-scp-path-traversal
description: The charm.land/wish/v2 and github.com/charmbracelet/wish libraries are vulnerable to path traversal attacks via the SCP protocol, allowing malicious clients to read or write arbitrary files, create directories outside the configured root, and enumerate files, potentially leading to remote code execution or data exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - scp
  - charmbracelet
  - wish
vendors:
  - Charm
products:
  - Wish
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-xjvp-7243-rg9h
rules:
  - title: Detect SCP Path Traversal via Filename
    description: Detects attempts to exploit path traversal vulnerabilities in SCP servers by identifying filenames containing '..' sequences or path separators during file uploads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect SCP Path Traversal via Filepath
    description: Detects attempts to exploit path traversal vulnerabilities in SCP servers by identifying filepaths containing '..' sequences used during file downloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The `charm.land/wish/v2` and `github.com/charmbracelet/wish` libraries are susceptible to path traversal vulnerabilities within their SCP middleware. This flaw allows an attacker to bypass intended directory restrictions and access files and directories outside the designated root. Specifically, versions of `charm.land/wish/v2` up to commit `72d67e6` and likely all v1 versions of `github.com/charmbracelet/wish` are affected due to insufficient input validation in the `fileSystemHandler.prefixed()` method. An authenticated SSH user, or potentially an unauthenticated user in default configurations, can exploit this to read sensitive files, write malicious files to arbitrary locations, create directories, and enumerate files outside the intended root directory, ultimately risking remote code execution and data breaches.

## Attack Chain

1. An attacker establishes an SSH connection to a vulnerable server.
2. The attacker initiates an SCP session, either to upload (`scp -t`) or download (`scp -f`) files.
3. If uploading files, the attacker crafts SCP protocol messages containing filenames with `../` sequences to traverse directories outside the intended root. The vulnerable regexes `reNewFile` and `reNewFolder` are exploited.
4. If downloading files, the attacker specifies a file path containing `../` sequences as an argument to the `scp` command, such as `scp user@host:../../../etc/passwd`.
5. The `fileSystemHandler.prefixed()` method fails to properly sanitize the path, resulting in a path outside the configured root directory.
6. The attacker reads arbitrary files on the server if the SCP session was initiated with the `-f` flag and a crafted filepath.
7. The attacker writes arbitrary files to the server if the SCP session was initiated with the `-t` flag and a crafted filename, by exploiting the flawed logic in `scp/copy_from_client.go`.
8. Successful exploitation can lead to remote code execution by overwriting critical system files or data exfiltration by reading sensitive information.

## Impact

Successful exploitation of this path traversal vulnerability allows an authenticated SSH user (or unauthenticated in default configurations) to perform critical actions. This includes writing arbitrary files, enabling remote code execution via cron jobs, SSH authorized\_keys, shell profiles, or systemd units, leading to full system compromise. Attackers can also read arbitrary files accessible to the server process, such as `/etc/shadow`, private keys, database credentials, and application secrets, causing sensitive data exposure. The creation of arbitrary directories and the enumeration of files outside the root directory further expand the attacker's control and reconnaissance capabilities.

## Recommendation

*   Apply the provided remediation to the `prefixed()` function to enforce root containment, ensuring that all paths resolve within the intended directory. Specifically, implement the corrected `prefixed()` function to sanitize the input path (reference: Remediation section in the content).
*   Implement filename sanitization in `copy_from_client.go` to reject filenames containing path separators or `..` components during file uploads (reference: Remediation section in the content).
*   Deploy the Sigma rule "Detect SCP Path Traversal via Filename" to identify attempts to exploit the vulnerability by detecting suspicious filenames during SCP file transfers.
*   Deploy the Sigma rule "Detect SCP Path Traversal via Filepath" to identify attempts to exploit the vulnerability by detecting suspicious filepaths during SCP file downloads.
