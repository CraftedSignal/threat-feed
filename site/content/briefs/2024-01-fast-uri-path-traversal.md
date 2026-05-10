---
title: fast-uri Path Traversal Vulnerability via Percent-Encoded Dot Segments
slug: 2024-01-fast-uri-path-traversal
description: fast-uri versions 3.1.0 and earlier are vulnerable to path traversal due to decoding percent-encoded path separators and dot segments before dot-segment removal, potentially leading to bypasses of path-based policy enforcement.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - defense-evasion
  - javascript
products:
  - fast-uri (<= 3.1.0)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
cves:
  - id: CVE-2026-6321
    cvss: 7.5
    epss: 0.0003
references:
  - https://github.com/advisories/GHSA-q3j6-qgpj-74h6
rules:
  - title: Detect fast-uri Path Traversal Attempts via URL Normalization
    description: Detects CVE-2026-6321 exploitation — HTTP requests with percent-encoded dot segments or path separators in the URI, potentially indicating path traversal attempts against applications using fast-uri.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect fast-uri Path Traversal Attempts via Double Encoding
    description: Detects requests with double-encoded dot segments or path separators, a common technique used to bypass simple URL validation filters before fast-uri normalization.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

fast-uri, a JavaScript library used for URI parsing and normalization, is susceptible to a path traversal vulnerability (CVE-2026-6321) in versions 3.1.0 and earlier. The vulnerability arises from the library's decoding of percent-encoded path separators (`%2F`) and dot segments (`%2E`) before applying dot-segment removal during URI normalization. This can cause distinct URIs to collapse onto the same normalized path, potentially allowing attackers to bypass path-based access controls. Applications that rely on fast-uri for URL normalization or comparison may be vulnerable. Defenders should upgrade to fast-uri version 3.1.1 or later to remediate this issue.

## Attack Chain

1. An attacker crafts a malicious URL containing percent-encoded dot segments (e.g., `%2E%2E`) or path separators (e.g., `%2F`).
2. The attacker supplies the crafted URL to a vulnerable application that uses `fast-uri` for URL processing, comparison, or normalization.
3. The `fast-uri` library decodes the percent-encoded characters before performing dot-segment removal.
4. The decoded path segments are processed, potentially leading to path traversal (e.g., `public/%2e%2e/admin` becomes `public/../admin`).
5. The `normalize()` or `equal()` functions in `fast-uri` further process the URI, resulting in an unexpected final path (e.g., `public/../admin` becomes `/admin`).
6. The application uses the normalized URL to make access control decisions, believing the user is accessing a different resource than intended.
7. The attacker gains unauthorized access to restricted resources or functionality.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass path-based access controls in applications utilizing the vulnerable versions of `fast-uri`. This can result in unauthorized access to sensitive data, modification of configurations, or execution of arbitrary code, depending on the application's functionality and the resources exposed. The severity of the impact is highly dependent on the specific application and its security architecture.

## Recommendation

*   Upgrade to `fast-uri` version 3.1.1 or later to patch CVE-2026-6321, as indicated in the advisory.
*   Deploy the Sigma rule "Detect fast-uri Path Traversal Attempts via URL Normalization" to identify potential exploitation attempts in web server logs.
