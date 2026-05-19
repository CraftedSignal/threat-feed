---
title: zrok 'copy' Path Traversal Vulnerability (CVE-2026-45576)
slug: 2026-05-zrok-path-traversal
description: A path traversal vulnerability exists in zrok copy (CVE-2026-45576) where an attacker-controlled WebDAV or zrok drive can write files outside the destination root by manipulating the DAV `href` response.
date: "2026-05-19T15:39:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - webdav
  - zrok
vendors:
  - OpenZiti
products:
  - zrok/v2
  - zrok
references:
  - https://github.com/advisories/GHSA-c656-jcx2-7pqj
  - CVE-2026-45576
rules:
  - title: Detect CVE-2026-45576 Exploitation — zrok Path Traversal File Write
    description: Detects CVE-2026-45576 exploitation — File creation outside the intended zrok target directory due to path traversal.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect CVE-2026-45576 Exploitation — zrok Path Traversal File Write (Linux)
    description: Detects CVE-2026-45576 exploitation — File creation outside the intended zrok target directory due to path traversal (Linux).
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A path traversal vulnerability has been identified in the `zrok copy` command, affecting versions prior to 2.0.3 and versions 0.4.23 through 1.1.11. The vulnerability, tracked as CVE-2026-45576, allows a malicious actor controlling a WebDAV or zrok drive to write files outside the intended destination root on a victim's system. This is achieved by manipulating the DAV `href` response to include path traversal sequences like `/../` which, when processed by the `FilesystemTarget.WriteStream` function, allows writing arbitrary files within the sharing user's credentials. This poses a significant risk of sensitive information being overwritten.

## Attack Chain

1. Bob sets up a malicious WebDAV server or a zrok drive.
2. Bob crafts a DAV `href` response containing path traversal sequences, such as `/../outside.txt`.
3. Alice executes the `zrok2 copy` command, specifying Bob's malicious WebDAV server or zrok drive as the source and a local directory as the destination.
4. The `zrok2 copy` process retrieves the directory listing from Bob's server, including the crafted `href` value.
5. The `zrok2 copy` process stores the malicious path in the source inventory.
6. The `FilesystemTarget.WriteStream` function receives the malicious path from the source inventory.
7. The `FilesystemTarget.WriteStream` function joins the attacker-controlled path with the target root path.
8. The file `outside.txt` is created (or overwritten) outside Alice's specified target directory, with Alice's credentials.

## Impact

Successful exploitation of CVE-2026-45576 allows a malicious user with access to a zrok share to traverse the directory tree arbitrarily on the system where the `zrok copy` command is executed. This can lead to the overwriting of sensitive information, potentially causing data loss, system instability, or privilege escalation if critical system files are targeted. The number of victims and the scope of impact depend on the privileges of the user running `zrok copy` and the contents of the files that are overwritten.

## Recommendation

*   Upgrade to `zrok/v2` version 2.0.3 or later to patch CVE-2026-45576.
*   Upgrade `zrok` versions between 0.4.23 and 1.1.11 (inclusive) to a patched version.
*   Monitor file creation events for unexpected write operations outside the intended target directory using a file integrity monitoring system, and deploy the provided Sigma rules.
