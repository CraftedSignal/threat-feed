---
title: goshs Unauthenticated Arbitrary File Deletion via Path Traversal
slug: 2026-04-goshs-path-traversal
description: The goshs application is vulnerable to unauthenticated path traversal (CVE-2026-35471) due to a missing return statement in the `deleteFile()` function, allowing attackers to delete arbitrary files and directories using a crafted GET request.
date: "2026-04-04T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
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

The goshs application, a simple static file server written in Go, is vulnerable to a path traversal vulnerability (CVE-2026-35471). This flaw exists within the `deleteFile` function (`httpserver/handler.go`) due to a missing `return` statement after a check for path traversal attempts using `..`. Specifically, if a request contains double-encoded path traversal sequences (e.g., `%252e%252e`), the check fails to prevent subsequent file deletion. This vulnerability, present in versions prior to 1.1.5-0.20260401172448-237f3af891a9, allows an unauthenticated attacker to delete arbitrary files and directories on the server. The vulnerability affects default configurations of goshs, requiring no authentication or specific flags to be set.

## Attack Chain

1.  The attacker identifies a goshs instance running a vulnerable version (prior to 1.1.5-0.20260401172448-237f3af891a9).
2.  The attacker crafts a GET request to a file path containing double-encoded path traversal sequences (`%252e%252e`) to bypass the path traversal check in `deleteFile()`.
3.  The GET request includes the `?delete` parameter to trigger the file deletion logic.
4.  The `deleteFile()` function receives the request and decodes the path, but the missing `return` after the path traversal check allows the execution to continue.
5.  The `os.RemoveAll()` function is called with the manipulated path, leading to the deletion of arbitrary files or directories outside the intended webroot.
6.  The server responds with HTTP status code 200, even if the file deletion was successful or resulted in an error.
7. The attacker verifies the deletion of the targeted file/directory.

## Impact

Successful exploitation of this path traversal vulnerability allows an unauthenticated attacker to delete any file or directory accessible to the goshs process. This could lead to data loss, system instability, or complete compromise of the server if critical system files are deleted. While the exact number of vulnerable instances is unknown, any organization using goshs versions prior to 1.1.5-0.20260401172448-237f3af891a9 is at risk.

## Recommendation

*   Upgrade to goshs version 1.1.5-0.20260401172448-237f3af891a9 or later to patch CVE-2026-35471.
*   Deploy the Sigma rule "Detect goshs Path Traversal Attempt via URL Encoding" to identify ongoing exploitation attempts based on double-encoded path traversal sequences in HTTP requests.
*   Monitor web server logs for GET requests containing double-encoded ".." sequences and the "?delete" parameter, indicative of exploitation attempts.
