---
title: SiYuan Path Traversal via Double URL Encoding in `/export/` Endpoint
slug: 2026-04-siyuan-path-traversal
description: SiYuan is vulnerable to path traversal via double URL encoding in the `/export/` endpoint, bypassing an incomplete fix for CVE-2026-30869; an authenticated attacker can exploit this vulnerability to traverse directories and read arbitrary workspace files, including the SQLite database (`siyuan.db`), kernel log, and user documents due to a redundant `url.PathUnescape()` call in `serveExport()`.
date: "2026-04-22T20:55:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - siYuan
vendors:
  - siyuan
products:
  - siyuan
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-30869
    cvss: 9.3
    epss: 0.00677
references:
  - https://github.com/advisories/GHSA-hjh7-r5w8-5872
iocs:
  - type: url
    value: https://github.com/user-attachments/files/26866234/poc.zip
    context: Proof-of-concept exploit code
ioc_counts:
  url: 1
rules:
  - title: Detect SiYuan Path Traversal Attempt
    description: Detects attempts to exploit the SiYuan path traversal vulnerability by monitoring for double URL encoded characters in requests to the `/export/` endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect SiYuan Database File Access via Export
    description: Detects attempts to access the SiYuan database file via the /export/ endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SiYuan is vulnerable to a path traversal vulnerability (CVE-2026-30869) due to a redundant `url.PathUnescape()` call within the `serveExport()` function. The vulnerability exists in versions prior to 3.6.5. This flaw allows an authenticated attacker, including low-privilege users with Publish/Reader roles, to bypass intended security restrictions and access sensitive files stored within the SiYuan workspace. The initial fix attempted with `IsSensitivePath()` proved insufficient as it did not address the core issue of double URL decoding. An attacker can exploit this vulnerability by using double URL encoded characters in a crafted HTTP request, allowing them to read arbitrary files such as the complete SQLite document database (`siyuan.db`), kernel logs, and other critical files.

## Attack Chain

1.  An authenticated attacker sends a GET request to the `/export/` endpoint with a double URL encoded path, such as `/export/%252e%252e/siyuan.db`.
2.  The Go HTTP server decodes the initial layer of URL encoding, transforming `%25` into `%`, resulting in a path like `/export/%2e%2e/siyuan.db`.
3.  The path cleaner does not recognize `%2e%2e` as directory traversal, so it passes through.
4.  The `serveExport()` function then calls `url.PathUnescape()` on the path, decoding `%2e%2e` into `..`.
5.  The `filepath.Join()` function concatenates the `exportBaseDir` with the now decoded path, e.g., `<workspace>/../siyuan.db`.
6.  The `IsSensitivePath()` check fails to block the request because it doesn't account for the decoded path or specific database files in the `temp/` directory.
7.  The attacker successfully retrieves the contents of the `siyuan.db` file, which contains the complete document database.
8.  The attacker repeats the process to access other sensitive files within the workspace, such as `siyuan.log`, `blocktree.db`, and `asset_content.db`.

## Impact

Successful exploitation of this vulnerability allows an attacker to exfiltrate sensitive data, including the entire SQLite document database, potentially containing all user documents, attributes, and search indexes. The attacker can also access the kernel log, which may contain internal server paths, versions, configuration details, and error messages. This information disclosure could lead to further compromise of the system. While the number of victims is unknown, any SiYuan instance running a version prior to 3.6.5 is potentially vulnerable.

## Recommendation

*   Upgrade SiYuan to version 3.6.5 or later to remediate the vulnerability.
*   Deploy the provided Sigma rule `Detect SiYuan Path Traversal Attempt` to detect attempts to exploit this vulnerability by monitoring for double URL encoded characters in requests to the `/export/` endpoint.
*   Monitor web server logs for requests to the `/export/` endpoint containing `%252e%252e` to identify potential exploitation attempts.
*   Consider implementing a more robust path validation mechanism within the `serveExport()` function that properly handles URL decoding and directory traversal attempts.
