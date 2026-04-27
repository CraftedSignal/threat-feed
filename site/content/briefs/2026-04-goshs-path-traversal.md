---
title: goshs Unauthenticated Arbitrary File Deletion via Path Traversal
slug: 2026-04-goshs-path-traversal
description: The goshs application is vulnerable to unauthenticated path traversal (CVE-2026-35471) due to a missing return statement in the `deleteFile()` function, allowing attackers to delete arbitrary files and directories using a crafted GET request.
date: "2026-04-04T12:00:00Z"
severities:
  - critical
tags:
  - path-traversal
  - file-deletion
  - goshs
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Uncommon Processes
references:
  - https://github.com/advisories/GHSA-6qcc-6q27-whp8
rules:
  - title: Detect goshs Path Traversal Attempt via URL Encoding
    description: Detects potential path traversal attempts in goshs by looking for double-encoded '..' sequences in the URL with the 'delete' parameter.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect goshs Arbitrary File Deletion - os.RemoveAll syscall
    description: Detects calls to the os.RemoveAll syscall which would indicate an arbitrary file deletion, requires syscall auditing to be enabled.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - syscall
      - linux
rules_count: 2
---

The goshs application, a simple static file server written in Go, is vulnerable to a path traversal vulnerability (CVE-2026-35471). This flaw exists within the `deleteFile` function (`httpserver/handler.go`) due to a missing `return` statement after a check for path traversal attempts using `..`. Specifically, if a request contains double-encoded path traversal sequences (e.g., `%252e%252e`), the check fails to prevent subsequent file deletion. This vulnerability, present in versions prior to…
