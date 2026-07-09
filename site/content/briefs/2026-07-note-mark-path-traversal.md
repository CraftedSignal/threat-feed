---
title: Note Mark Path Traversal Vulnerability (CVE-2026-50553)
slug: 2026-07-note-mark-path-traversal
description: A low-privilege authenticated user can exploit CVE-2026-50553, a path traversal vulnerability in Note Mark versions up to v0.19.4, by crafting a malicious 'slug' parameter in API requests, leading to arbitrary file write outside the intended export directory when an administrator runs the 'migrate export' command, potentially allowing root-level privilege escalation and code execution.
date: "2026-07-09T13:43:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - privilege-escalation
  - web-application
  - rce
  - go
  - linux
vendors:
  - Enchant97
products:
  - Note Mark <= v0.19.4
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Attacker registers / uses any normal user account.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: escalating to code execution as root.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: writing to [...] systemd unit directories
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: writing to /etc/cron.d/
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rqrh-8wpv-x7hh
rules:
  - title: Detect Note Mark Path Traversal Attempt (CVE-2026-50553)
    description: Detects CVE-2026-50553 exploitation - HTTP POST request to Note Mark's book/note creation API containing path traversal sequences in the 'slug' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1133
    data_sources:
      - webserver
rules_count: 1
---

Note Mark, a note-taking application developed by Enchant97, is affected by CVE-2026-50553, a critical path traversal vulnerability present in versions up to and including v0.19.4. This vulnerability stems from an unanchored regex pattern (`[a-z0-9-]+`) used for validating 'slug' parameters in book and note creation APIs, allowing malicious input such as `../../../../../../tmp/escape` to be accepted and stored verbatim. When an administrator subsequently runs the `note-mark migrate export` or `export-v1` CLI commands - often with root privileges in environments like Docker - the application uses `path.Join` with these unsanitized slugs, resolving the traversal sequences. This allows an authenticated attacker to cause arbitrary directories to be created and files written to locations outside the designated export directory, enabling privilege escalation to root through mechanisms like writing to `/etc/cron.d/` or systemd unit directories. The vulnerability is a sibling of GHSA-g49p-4qxj-88v3, affecting similar code paths within the export functionality.

## Attack Chain

1. An attacker, as a low-privilege authenticated user, registers or logs into a Note Mark instance.
2. The attacker sends a `POST` request to the `/api/books` or `/api/notes` endpoint, including a crafted `slug` parameter containing directory traversal sequences (e.g., `../../../../../../etc/cron.d/x`).
3. Note Mark's OpenAPI/huma validation, due to an unanchored `pattern:"[a-z0-9-]+"` regex, incorrectly validates and accepts the malicious slug.
4. The application stores this malicious slug verbatim in its database, associated with the attacker's created book or note.
5. At a later time, an administrator executes the `note-mark migrate export` or `note-mark migrate export-v1` CLI command, typically with root privileges (e.g., in a Docker container).
6. During the export process, the application uses `path.Join` to construct file paths, incorporating the unsanitized, malicious slug retrieved from the database.
7. `path.Join` resolves the `../` segments, causing `os.MkdirAll` to create an attacker-controlled directory and `os.Create` to write the note's `_index.md` file to an arbitrary location outside the intended export directory (e.g., `/etc/cron.d/x`).
8. By writing to critical system directories, the attacker achieves arbitrary code execution as root, enabling privilege escalation and persistent access.

## Impact

This vulnerability allows any registered user to facilitate arbitrary file writes with root privileges on the server hosting Note Mark, given that an administrator later performs a routine data export. If the export command is run as root (a common practice in Docker deployments or by system administrators), an attacker can write malicious cron jobs (`/etc/cron.d/`) or systemd unit files to achieve remote code execution as root. The potential damage includes full system compromise, data theft, or system disruption. This vulnerability poses a direct and severe risk to the integrity and confidentiality of the affected systems.

## Recommendation

* Patch CVE-2026-50553 immediately by upgrading Note Mark to a version beyond v0.19.4 that includes the fix for GHSA-rqrh-8wpv-x7hh.
* Deploy the `Detect Note Mark Path Traversal Attempt (CVE-2026-50553)` Sigma rule to your SIEM to identify attempts to inject malicious slugs via the API.
* Ensure that log sources for `webserver` category are properly configured to capture HTTP request details, including method, URI stem, and query parameters, to activate the rule above.
* Regularly review administrative practices to ensure that backup and export operations are performed with the minimum necessary privileges and within isolated environments where possible.
