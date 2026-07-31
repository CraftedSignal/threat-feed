---
title: Thumbor Path Traversal via URL Decoding Bypass
slug: 2026-07-thumbor-path-traversal
description: Thumbor version 7.7.7 and earlier is vulnerable to arbitrary file read via a path traversal flaw in file_loader.py, where security checks are performed before decoding percent-encoded traversal sequences.
date: "2026-07-31T19:20:49Z"
lastmod: "2026-07-31T19:29:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - hmac-bypass
  - image-processing
  - cve-2026-53501
vendors:
  - Thumbor
products:
  - Thumbor (<= 7.7.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The file_loader performs unquote() on the file path AFTER the abspath() + startswith() security check.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker can trigger extremely large resizes (CPU/memory exhaustion) and cause denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-53502
references:
  - https://github.com/advisories/GHSA-cj54-hpcc-gj6h
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53502
  - https://github.com/advisories/GHSA-phj3-59pf-cp83
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53505
  - https://github.com/advisories/GHSA-cqjp-jf4r-h5q9
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53503
  - https://github.com/advisories/GHSA-mw3h-qjxj-6xg9
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-53501
iocs:
  - type: url
    value: http://thumbor-host:8888/unsafe/filters:watermark(%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd,0,0,100)/some-valid-image.jpg
ioc_counts:
  url: 1
rules:
  - title: Detect CVE-2026-53502 Exploitation - Path Traversal via Watermark Filter
    description: Detects exploitation attempts against CVE-2026-53502 by identifying double-encoded path traversal sequences in watermark filter requests
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-31T19:20:56Z"
    level: L1
    summary: 'merged source coverage: Thumbor Proportion Filter Unbounded Resize Denial of Service'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-phj3-59pf-cp83
  - at: "2026-07-31T19:21:02Z"
    level: L1
    summary: 'merged source coverage: Remote Denial of Service in Thumbor Convolution Filter'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-cqjp-jf4r-h5q9
  - at: "2026-07-31T19:29:08Z"
    level: L2
    summary: 'merged source coverage: Thumbor HMAC Validation Bypass via URL Manipulation'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-mw3h-qjxj-6xg9
---

Thumbor, an open-source image processing service, contains a path traversal vulnerability (CVE-2026-53502) in its `file_loader` component. The flaw arises because the application performs security validation - using `abspath()` and `startswith()` - on the file path before calling `unquote()`. Attackers can supply double-percent-encoded traversal sequences, such as `%252e%252e`, which evade the initial security check by being treated as literal directory names. Once the check passes, `unquote()` decodes these sequences into standard traversal characters (`..`), allowing the loader to traverse outside the designated root directory. 

This issue specifically impacts configurations where `file_loader` is used and the watermark or frame filters are enabled. An attacker can leverage this to read arbitrary files from the server's filesystem, including sensitive configuration files or keys, and receive the file contents overlaid as an image if the data can be parsed as an image format. This affects Thumbor versions 7.7.7 and below.

## Attack Chain

1. Attacker constructs a malicious URL targeting a Thumbor watermark filter endpoint (e.g., `/unsafe/filters:watermark(...)`).
2. Attacker embeds double-encoded path traversal sequences (e.g., `%252e%252e`) into the watermark image path parameter.
3. The web server (Tornado) decodes the first layer of encoding, passing `%2e%2e` to the application logic.
4. The `file_loader` receives the path and performs `abspath()`, which treats the literal `%2e%2e` as a directory name, causing the `startswith(ROOT)` security check to return True.
5. The `file_loader` identifies the path as non-existent (as the literal directory doesn't exist) and proceeds to call `unquote()`.
6. The `unquote()` function decodes `%2e%2e` into `..`, effectively enabling directory traversal.
7. The application opens the file requested from the filesystem, traversing outside the `FILE_LOADER_ROOT_PATH`.
8. The file content is returned to the user, potentially displaying sensitive file data as an image artifact.

## Impact

Successful exploitation results in unauthorized arbitrary file read on the host server. This allows attackers to access critical system files, application configuration files, and environment secrets, which may lead to further compromise of the underlying infrastructure or exfiltration of sensitive organizational data.

## Recommendation

- Upgrade Thumbor to a version that performs URL decoding prior to filesystem path validation.
- Implement strict ingress filtering on web application firewalls to block double-percent-encoded characters (`%252e`) in query parameters targeting watermark or frame filters.
- Deploy the Sigma rule below to detect attempts to inject encoded traversal sequences into the application.
- Audit logs for HTTP 200 responses originating from watermark or frame filter endpoints that involve character strings suggestive of path traversal.
