---
title: Note Mark Arbitrary File Write via Path Traversal Leads to Remote Code Execution
slug: 2024-01-note-mark-rce
description: Note Mark is vulnerable to arbitrary file write via path traversal in asset names, leading to remote code execution by overwriting system binaries such as /bin/bash.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - rce
  - web-application
vendors:
  - enchant97
products:
  - note-mark/backend
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-g49p-4qxj-88v3
rules:
  - title: Detect Note Mark Asset Upload with Path Traversal Filename
    description: Detects asset upload with path traversal sequences in the X-Name header, indicative of CVE-2026-44522 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Note Mark Migrate Export with Path Traversal Filename
    description: Detects command execution of `note-mark migrate export-v1` or `note-mark migrate export` with path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Overwritten /bin/bash
    description: Detects modification of /bin/bash with a non-standard shebang, potentially indicating CVE-2026-44522 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
      - privilege_escalation
    techniques:
      - T1053.005
      - T1543.002
    data_sources:
      - file_event
      - linux
rules_count: 3
---

Note Mark versions 0.19.2 and earlier contain an arbitrary file write vulnerability that leads to remote code execution. Authenticated users can upload assets to notes via `POST /api/notes/{noteID}/assets`, with the asset filename taken directly from the `X-Name` HTTP header. The application fails to sanitize this filename, storing it directly in the database. When an administrator subsequently runs the data export CLI commands (`note-mark migrate export-v1` or `note-mark migrate export`), the stored asset name is passed into `filepath.Join()` calls. An attacker-controlled asset name containing directory traversal sequences (e.g., `../`) allows writing files to arbitrary locations, which can be escalated to RCE by overwriting system binaries, such as `/bin/bash`. The vulnerability is present in Note Mark's backend component.

## Attack Chain

1. Attacker registers an account and authenticates to the Note Mark application.
2. Attacker creates a notebook using a `POST` request to `/api/books`.
3. Attacker creates a note within the notebook using a `POST` request to `/api/books/<BOOK_ID>/notes`.
4. Attacker uploads an asset with a malicious payload and a path traversal filename in the `X-Name` header to `/api/notes/<NOTE_ID>/assets`. The `X-Name` header contains a path traversal sequence targeting a sensitive file like `/bin/bash`.
5. The application stores the unsanitized filename (including the path traversal) in the database.
6. An administrator triggers a data export using `note-mark migrate export-v1 --export-dir /data/backup` or `note-mark migrate export`.
7. The export process uses the unsanitized filename in `filepath.Join()`, causing a file to be written to the attacker-specified location (e.g., overwriting `/bin/bash`).
8. The next time `bash` is invoked, the attacker's payload executes, resulting in code execution as root.

## Impact

Successful exploitation allows an attacker to overwrite arbitrary files on the system with root privileges, leading to complete system compromise. Overwriting `/bin/bash` results in RCE the next time any user invokes `bash`. The number of affected installations is unknown, but the vulnerability exists in version 0.19.2 and earlier.

## Recommendation

*   Deploy the Sigma rule to detect asset uploads with path traversal sequences in the `X-Name` header.
*   Apply `filepath.Base()` to the `X-Name` header value in `backend/handlers/assets.go` before storing it in the database, as described in the advisory.
*   Apply `filepath.Base()` to `asset.Name` in `backend/cli/migrate.go` at lines 328 and 223 before using it in file path construction.
*   Upgrade to a patched version of Note Mark which addresses CVE-2026-44522.
