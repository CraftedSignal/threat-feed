---
title: Goshs WebDAV MOVE Method Bypasses No-Delete Flag
slug: 2026-07-goshs-webdav-move-bypass
description: A critical vulnerability (CVE-2026-64863) in the goshs WebDAV server, affecting versions up to 2.1.3, allows an attacker to bypass the `--no-delete` security flag using the `MOVE` HTTP method, leading to unauthorized deletion of source files or overwriting of existing destination files, impacting data integrity.
date: "2026-07-28T22:04:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - webdav
  - vulnerability
  - file-deletion
  - data-destruction
  - server
  - golang
vendors:
  - patrickhener
products:
  - goshs <= 2.1.3
  - goshs <= 1.1.4
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: '`MOVE` deletes the source file (rename removes it from its original path), and with `Overwrite: T` it additionally performs an explicit `RemoveAll` on the destination.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-hq33-8jgp-8qq3
rules:
  - title: Detects CVE-2026-64863 Exploitation - Goshs WebDAV MOVE Bypass
    description: Detects exploitation of CVE-2026-64863, where the goshs WebDAV server's `--no-delete` flag is bypassed by the `MOVE` HTTP method, potentially leading to unauthorized file deletion or overwrite.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, tracked as CVE-2026-64863, has been discovered in the `goshs` WebDAV server (versions up to 2.1.3 and 1.1.4). The `--no-delete` command-line flag, intended to prevent file deletion and overwriting, is ineffective against the WebDAV `MOVE` HTTP method. This logical flaw allows a remote attacker to bypass a configured security control, enabling unauthorized deletion of source files or overwriting of existing destination files, even when the server operator believes deletion is disabled. The issue stems from the server's `wdGuard` handler, which incorrectly classifies `MOVE` as a write-only operation, thus failing to apply the `fs.NoDelete` check to it. This oversight defeats the security intent of the `--no-delete` flag, jeopardizing data integrity for systems using `goshs` to serve files with deletion restrictions.

## Attack Chain

1. An attacker identifies a `goshs` server running with WebDAV enabled and the `--no-delete` flag configured (e.g., `goshs --webdav --no-delete`).
2. The attacker attempts to `DELETE` a file, which is correctly blocked by the server, returning an HTTP 403 Forbidden status, confirming the `--no-delete` flag is active for the `DELETE` verb.
3. The attacker crafts an HTTP `MOVE` request targeting a sensitive file (e.g., `/secret.txt`) with a `Destination` header pointing to a new path (e.g., `/gone.txt`).
4. The server processes the `MOVE` request, effectively deleting `/secret.txt` from its original location and moving its content to `/gone.txt`, bypassing the `--no-delete` control.
5. Alternatively, the attacker crafts an HTTP `MOVE` request with an `Overwrite: T` header, targeting a source file (e.g., `/gone.txt`) and a destination path that corresponds to an existing, sensitive file (e.g., `/victim.txt`).
6. The server processes this `MOVE` request, first invoking `RemoveAll` on the existing `/victim.txt` and then moving the content of `/gone.txt` to `/victim.txt`.
7. This results in the original content of `/victim.txt` being destroyed and replaced with the attacker-controlled content, allowing data destruction or overwriting, despite the `--no-delete` flag.

## Impact

The impact of CVE-2026-64863 is significant for `goshs` deployments where file integrity and prevention of deletion/overwriting are paramount. If an operator sets up `goshs` with `--no-delete` to protect critical data, such as archived artifacts or confidential documents, any authenticated (or unauthenticated, if no ACLs are in place) WebDAV client can exploit this flaw. This allows an attacker to rename confidential files away, effectively deleting them from their expected location, or worse, overwrite existing sensitive files with arbitrary content. This directly violates the intended security posture, leading to data loss, data corruption, or the unavailability of critical information, undermining the trust in the configured security controls.

## Recommendation

* **Patch CVE-2026-64863**: Update `goshs` to a patched version immediately. Monitor the official GitHub repository for releases that address this vulnerability.
* **Deploy the Sigma rule in this brief**: Implement the provided Sigma rule into your SIEM to detect suspicious WebDAV `MOVE` requests, particularly those including the `Overwrite: T` header.
* **Enable webserver logging**: Ensure comprehensive logging for your `goshs` instances, including HTTP method, URI, status codes, and request headers (specifically `Overwrite`). This is crucial for the provided Sigma rule.
