---
title: SiYuan Path Traversal Vulnerability (CVE-2026-54066) via Double URL Encoding
slug: 2026-07-siyuan-path-traversal
description: An incomplete fix for CVE-2026-41894 in SiYuan's 'publish mode' allows unauthenticated remote attackers to perform path traversal by double URL-encoding '..' segments in requests to the '/assets/*path' route, leading to the read of arbitrary files within the 'WorkspaceDir'.
date: "2026-07-10T19:30:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - web-vulnerability
  - arbitrary-file-read
vendors:
  - SiYuan
products:
  - siyuan kernel (versions prior to 0.0.0-20260628153353-2d5d72223df4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can read arbitrary files inside WorkspaceDir by double-URL-encoding .. segments.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: 'Confirmed-readable files include: conf/conf.json — accessAuthCode SHA256 (offline crackable), API token, S3/WebDAV sync credentials. temp/siyuan.db, temp/blocktree.db, temp/asset_content.db — full notebook content (SQLite).'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Attacker can read arbitrary files inside WorkspaceDir.
    confidence_band: high
cves:
  - id: CVE-2026-54066
    cvss: 7.5
    epss: 0.01892
  - id: CVE-2026-41894
    epss: 0.00313
references:
  - https://github.com/advisories/GHSA-p4m3-mgmm-c664
iocs:
  - type: url
    value: http://victim:6808/assets/%252e%252e/%252e%252e/conf/conf.json
ioc_counts:
  url: 1
rules:
  - title: Detect CVE-2026-54066 Exploitation - SiYuan Double URL-Encoded Path Traversal
    description: Detects CVE-2026-54066 exploitation - HTTP GET requests to SiYuan's /assets/ route containing double URL-encoded path traversal sequences (%252e%252e), indicating an attempt to read arbitrary files.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical path traversal vulnerability, tracked as CVE-2026-54066, affects the SiYuan note-taking application in its "publish mode" (anonymous read-only HTTP endpoint, typically port 6808). This flaw is a bypass of the previously incomplete fix for CVE-2026-41894. Unauthenticated remote attackers can exploit this by sending specially crafted HTTP GET requests containing double URL-encoded `..` segments to the `/assets/*path` route. This technique allows them to read arbitrary files from the `WorkspaceDir` outside the intended `DataDir` subtree, including sensitive files like `conf/conf.json` (containing API tokens and sync keys) and `temp/*.db` (full notebook content). The vulnerability stems from a second `url.PathUnescape` operation in a fallback function, coupled with an overly permissive access gate and the non-application of a sensitive path denylist to the `/assets/` route. The vulnerability has been verified against SiYuan v3.6.5 and affects versions prior to `0.0.0-20260628153353-2d5d72223df4`.

## Attack Chain

1. An unauthenticated remote attacker sends an HTTP GET request to the SiYuan instance's "publish mode" server (default port 6808), targeting the `/assets/*path` endpoint.
2. The request URL's `cs-uri-stem` contains double URL-encoded path traversal sequences, such as `/assets/%252e%252e/%252e%252e/target/file`.
3. The Gin router performs the initial URL decoding, receiving `context.Param("path")` with single URL-encoded segments (e.g., `/%2e%2e/%2e%2e/target/file`).
4. The `GetAssetAbsPath` function, within its fallback mechanism (`kernel/model/assets.go:548`), performs a second `url.PathUnescape` on the path.
5. This second decode converts the single URL-encoded `..` (`%2e%2e`) into literal `..` segments, which `filepath.Join` then processes to resolve a path outside the `DataDir` but still within the `WorkspaceDir`.
6. The `CheckAbsPathAccessableByPublishAccess` function evaluates the resolved absolute path. Since the path is outside `DataDir` (e.g., `WorkspaceDir/conf/conf.json`), it incorrectly returns `true`, bypassing further granular access checks.
7. Crucially, the `IsSensitivePath()` denylist, which is applied to the patched `/export/` route, is not called or enforced for the `/assets/*path` handler.
8. The `http.ServeFile` function then proceeds to serve the arbitrarily specified file from the `WorkspaceDir`, such as `conf/conf.json` or `temp/siyuan.db`, to the attacker.

## Impact

Successful exploitation allows an unauthenticated attacker to read any file within the SiYuan `WorkspaceDir`. This includes highly sensitive information such as: `conf/conf.json`, which contains the `accessAuthCode` SHA256 hash (vulnerable to offline cracking), API tokens, and S3/WebDAV sync credentials. Attackers can also access `temp/siyuan.db`, `temp/blocktree.db`, and `temp/asset_content.db`, which are SQLite databases containing the entire content of all notebooks. Additionally, `siyuan.log` can be exfiltrated, revealing internal paths and system information. Compromise of the `accessAuthCode` or API token provides full authenticated access to the kernel API, enabling complete read and write capabilities for all notebooks, and potentially escalating to further compromise if sync credentials are used elsewhere.

## Recommendation

* Patch SiYuan immediately to a version equal to or later than `0.0.0-20260628153353-2d5d72223df4` to remediate CVE-2026-54066.
* Deploy the `Detect CVE-2026-54066 Exploitation - SiYuan Double URL-Encoded Path Traversal` Sigma rule to your SIEM to identify attempts to exploit this vulnerability.
* Implement Web Application Firewall (WAF) rules to block HTTP GET requests containing the `%252e%252e` string in the URL path, specifically targeting `/assets/` endpoints, as identified in the IOC.
* Disable SiYuan's "publish mode" (anonymous read-only HTTP endpoint) if it is not explicitly required for your operational needs, reducing the attack surface.
