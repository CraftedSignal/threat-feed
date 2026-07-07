---
title: goshs WebDAV Listener Bypasses Access Restriction Flags
slug: 2026-07-goshs-webdav-flag-bypass
description: A vulnerability (CVE-2026-50138) in `goshs` versions up to `v2.0.9` allows an authenticated attacker to bypass intended access restriction flags like `--read-only`, `--upload-only`, and `--no-delete` when the WebDAV listener is enabled, leading to unauthorized file creation, modification, deletion, and content exfiltration on the server, compromising data integrity and confidentiality.
date: "2026-07-03T12:23:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webserver
  - misconfiguration
  - vulnerability
  - cve
vendors:
  - Patrick Hener
products:
  - goshs (<= v2.0.9)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: When `goshs` is launched with WebDAV enabled (`-w`), the mode-restriction flags `--read-only`, `--upload-only`, and `--no-delete` are enforced only on the primary HTTP port. The WebDAV port is wired straight to `golang.org/x/net/webdav.Handler` with no equivalent guard, so an authenticated WebDAV client can `PUT`, `DELETE`, `MKCOL`, `MOVE`, and `COPY` despite the operator's stated intent.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
    evidence: Any WebDAV client (curl, cadaver, Windows Explorer, Finder) can overwrite/delete files.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: '`--read-only` and `--no-delete` are silently downgraded to ''no protection'' on the WebDAV port. Any WebDAV client (curl, cadaver, Windows Explorer, Finder) can overwrite/delete files.'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: '`--upload-only` is also bypassed: WebDAV GET/PROPFIND still return file contents.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-3whc-qvhv-xqjp
---

A significant vulnerability, tracked as CVE-2026-50138, has been identified in the `goshs` HTTP server, specifically affecting versions `<= v2.0.9`. When `goshs` is configured to enable its WebDAV listener via the `-w` flag, crucial access restriction flags such as `--read-only`, `--upload-only`, and `--no-delete` are not properly enforced on the WebDAV port. This oversight allows an authenticated attacker to perform unauthorized file operations, including creating, overwriting, deleting, moving, and copying files, despite the administrator's explicit configuration to prevent such actions. Furthermore, even with `--upload-only` enabled, file contents can be retrieved via WebDAV `GET` or `PROPFIND` requests. The core issue lies in the WebDAV mux being directly wired to `golang.org/x/net/webdav.Handler` without the necessary guard logic present in the primary HTTP handler, fundamentally undermining data integrity and confidentiality assurances for affected `goshs` deployments.

## Attack Chain

1.  An administrator deploys `goshs` with WebDAV enabled (`-w`), a data directory (`-d`), basic authentication (`-b`), and restrictive flags like `--read-only` (`-ro`) or `--no-delete`, expecting the WebDAV share to enforce these restrictions.
2.  The attacker gains valid credentials for the `goshs` basic authentication, either through compromise or misconfiguration.
3.  The attacker connects to the `goshs` WebDAV port (e.g., `http://localhost:18001`) and authenticates.
4.  Despite `goshs` being configured with `--read-only`, the attacker sends an HTTP `PUT` request to create or overwrite a file on the WebDAV share (e.g., `curl -u admin:pw -X PUT http://localhost:18001/new_file.txt --data "malicious content"`).
5.  The `goshs` WebDAV handler, lacking enforcement of the `--read-only` flag, successfully processes the `PUT` request, creating or modifying `new_file.txt`.
6.  Similarly, the attacker sends an HTTP `DELETE` request to remove an existing file (e.g., `curl -u admin:pw -X DELETE http://localhost:18001/sensitive_data.txt`).
7.  The WebDAV handler bypasses the `--no-delete` flag, successfully deleting `sensitive_data.txt`.
8.  The attacker can further exfiltrate data by sending HTTP `GET` or `PROPFIND` requests, even if `--upload-only` was configured, revealing sensitive file contents.

## Impact

The vulnerability in `goshs` allows a complete bypass of intended access restrictions, leading to severe consequences for data integrity and confidentiality. Any operator utilizing `goshs` with WebDAV enabled and relying on flags like `--read-only` or `--no-delete` to protect sensitive directories from modification or deletion will find their data exposed. This can result in unauthorized data alteration, complete deletion of files, creation of malicious content, and unauthorized disclosure of confidential information. While no specific victim counts are provided, any organization using `goshs` up to version `v2.0.9` for sharing sensitive files in a restricted manner, especially as a "read-only" artifact delivery mechanism, is directly at risk.

## Recommendation

*   **Patch CVE-2026-50138 immediately**: Upgrade `goshs` to a version greater than `v2.0.9` once a fix is released.
*   **Review `goshs` deployments**: Operators running `goshs` with WebDAV enabled (`-w`) should re-evaluate their security posture, especially if relying on `--read-only`, `--upload-only`, or `--no-delete` flags.
*   **Implement network segmentation**: For `goshs` instances serving WebDAV, restrict network access to the WebDAV port to only trusted internal networks or specific IP addresses to limit exposure.
*   **Disable WebDAV if not strictly necessary**: If WebDAV functionality is not a core requirement, disable it entirely to mitigate the risk of CVE-2026-50138.
