---
title: Vite Dev Server `server.fs.deny` Bypass on Windows (CVE-2026-53571)
slug: 2026-06-vite-fs-deny-bypass
description: A high-severity vulnerability (CVE-2026-53571) in the Vite development server on Windows allows threat actors to bypass `server.fs.deny` restrictions, leading to information disclosure of sensitive files like `.env` or `tls.pem` via crafted HTTP requests utilizing NTFS Alternate Data Streams or 8.3 short names, impacting applications that expose the dev server to the network.
date: "2026-06-15T17:24:10Z"
lastmod: "2026-07-09T03:00:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vitejs:vite:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:voidzero:vite\+:*:*:*:*:*:node.js:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=5102680F-B61E-58F4-BFE2-6D894F92EE59&utm_source=rss&utm_medium=rss
tags:
  - information-disclosure
  - bypass
  - web-vulnerability
  - windows
  - development-server
vendors:
  - Vite
  - Vitejs
products:
  - Vite (>= 8.0.0, <= 8.0.15)
  - Vite (>= 7.0.0, <= 7.3.4)
  - Vite (<= 6.4.2)
  - vite-plus (<= 0.1.23)
  - Vite
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-53571
    cvss: 7.5
    epss: 0.00393
references:
  - https://github.com/advisories/GHSA-fx2h-pf6j-xcff
  - https://sploitus.com/exploit?id=5102680F-B61E-58F4-BFE2-6D894F92EE59&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: http://localhost:5173/.env::$DATA?raw
  - type: url
    value: http://localhost:5173/tls.pem::$DATA?raw
  - type: url
    value: https://sploitus.com/exploit?id=5102680F-B61E-58F4-BFE2-6D894F92EE59
ioc_counts:
  url: 3
rules:
  - title: Detects CVE-2026-53571 Exploitation - Vite ADS Bypass
    description: Detects exploitation attempts of CVE-2026-53571, a Vite dev server vulnerability, by identifying HTTP GET requests that leverage NTFS Alternate Data Stream (ADS) syntax (`::$DATA`) to bypass file access restrictions on Windows.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1552.001
    data_sources:
      - webserver
  - title: Detects CVE-2026-53571 Exploitation - Vite Raw Parameter Access
    description: Detects exploitation attempts of CVE-2026-53571 by identifying HTTP GET requests that include the '?raw' parameter in the query string, targeting common sensitive file extensions, which indicates an attempt to bypass Vite's server.fs.deny rules.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-07-09T03:00:50Z"
    level: L2
    summary: poc_available; added CVE-2026-53571
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=5102680F-B61E-58F4-BFE2-6D894F92EE59&utm_source=rss&utm_medium=rss
---

A critical information disclosure vulnerability, tracked as CVE-2026-53571, affects the Vite development server running on Windows. This flaw allows an attacker to bypass security restrictions imposed by `server.fs.deny`, which is designed to prevent direct access to sensitive files such as `.env` configurations or TLS certificates (`.crt`, `.pem`). The bypass occurs because Vite's deny logic fails to properly normalize Windows-specific path forms, specifically NTFS Alternate Data Streams (ADS) (e.g., `::$DATA`) and 8.3 short names. When an affected Vite dev server is explicitly exposed to the network (via `--host` or `server.host`), and sensitive files reside within allowed `server.fs.allow` directories on NTFS volumes or volumes with 8.3 short name generation enabled, an attacker can craft specific HTTP requests (e.g., `/.env::$DATA?raw`) to retrieve the contents of these protected files. This vulnerability affects npm/vite versions >= 8.0.0, <= 8.0.15; >= 7.0.0, <= 7.3.4; <= 6.4.2; and npm/vite-plus <= 0.1.23, posing a significant risk of sensitive information exfiltration for development environments.

## Attack Chain

1.  A developer initializes a Vite project and starts the development server on a Windows operating system.
2.  The Vite dev server is explicitly exposed to the network using the `--host` CLI option or the `server.host` configuration option.
3.  Sensitive files, such as `.env` or `tls.pem`, exist within directories allowed by `server.fs.allow` and are protected by `server.fs.deny`.
4.  An attacker, with network access to the exposed Vite dev server, crafts an HTTP GET request containing a Windows-specific alternate path form (e.g., `/.env::$DATA`) and the `?raw` parameter.
5.  Vite's `server.fs.deny` security check is performed against the unnormalized request path, which the logic incorrectly deems as allowed.
6.  The Windows operating system then resolves the `::$DATA` alternate data stream to the default data stream of the original sensitive file.
7.  Vite's dev server retrieves the content of the sensitive file (e.g., `.env`) and serves it in the HTTP response.
8.  The attacker successfully exfiltrates the contents of the sensitive file, leading to information disclosure (e.g., API keys, database credentials, certificates).

## Impact

Successful exploitation of CVE-2026-53571 leads to unauthorized information disclosure, potentially exposing sensitive data such as API keys, database credentials, or cryptographic keys (e.g., TLS certificates) that are stored in files like `.env` or `*.pem`. While directly impacting development environments, such breaches can provide attackers with critical intelligence or credentials to pivot into production systems or sensitive internal resources. The vulnerability primarily affects Vite development environments running on Windows that are inadvertently exposed to untrusted networks. The scope of victims depends on how widely exposed Vite dev servers with sensitive files exist; concrete numbers are not available, but the potential for access to development secrets is high.

## Recommendation

*   **Patch CVE-2026-53571**: Immediately update Vite to a patched version to remediate CVE-2026-53571. Refer to the GHSA advisory linked in the references for specific versions.
*   **Network Segmentation**: Ensure development servers, especially those running Vite, are not exposed to untrusted networks (e.g., the internet). Restrict access to `localhost` or internal subnets as much as possible.
*   **Deploy Detection Rules**: Implement the provided Sigma rules into your SIEM to detect exploitation attempts of CVE-2026-53571 based on suspicious `cs-uri-stem` and `cs-uri-query` patterns in webserver logs.
*   **Enable Webserver Logging**: Ensure detailed webserver access logs are enabled and ingested into your SIEM, specifically capturing `cs-uri-stem` and `cs-uri-query` to facilitate detection of the patterns identified in this brief.
