---
title: Microweber CMS Path Traversal Vulnerability (CVE-2026-65694)
slug: 2026-07-microweber-path-traversal
description: An unauthenticated path traversal vulnerability (CVE-2026-65694) in the static file controller of Microweber CMS, affecting versions through 2.0.20, allows remote attackers to read arbitrary files by supplying directory traversal sequences in the 'path' query parameter via a single unauthenticated HTTP GET request, potentially disclosing sensitive information like environment configuration files containing credentials or system files.
date: "2026-07-23T22:25:27Z"
lastmod: "2026-07-25T12:02:06Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=566642C7-D80C-5E20-9790-03A5CE91EF92&utm_source=rss&utm_medium=rss
tags:
  - web-vulnerability
  - path-traversal
  - cms
  - webserver
vendors:
  - Microweber
products:
  - Microweber CMS
  - Microweber CMS ≤ 2.0.20 and current master
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: allows remote attackers to read arbitrary files by supplying directory traversal sequences in the path query parameter. ... disclosing sensitive files such as environment configuration files containing credentials and system files.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: allows remote attackers to read arbitrary files by supplying directory traversal sequences in the path query parameter. ... disclosing sensitive files such as environment configuration files containing credentials and system files.
    confidence_band: high
cves:
  - id: CVE-2026-65694
    cvss: 7.5
    epss: 0.00793
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65694
  - https://sploitus.com/exploit?id=566642C7-D80C-5E20-9790-03A5CE91EF92&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=566642C7-D80C-5E20-9790-03A5CE91EF92
  - type: url
    value: https://github.com/microweber/microweber
ioc_counts:
  url: 2
rules:
  - title: Detects CVE-2026-65694 Exploitation - Microweber Path Traversal
    description: Detects CVE-2026-65694 exploitation attempts targeting Microweber CMS via path traversal sequences in the 'path' query parameter.
    platform: sigma
    severity: high
    tactics:
      - collection
      - discovery
    techniques:
      - T1005
      - T1083
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-25T12:02:06Z"
    level: L2
    summary: poc_available; OS linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=566642C7-D80C-5E20-9790-03A5CE91EF92&utm_source=rss&utm_medium=rss
---

A critical path traversal vulnerability, tracked as CVE-2026-65694, has been identified in Microweber CMS versions up to and including 2.0.20. This flaw resides within the static file controller, specifically due to the `normalize_path()` function's failure to properly sanitize or strip directory traversal sequences provided in the `path` query parameter of HTTP GET requests. Unauthenticated remote attackers can leverage this vulnerability to bypass intended access controls and read arbitrary files on the server. Exploitation requires only a single unauthenticated HTTP GET request, making it highly accessible to attackers. Successful exploitation can lead to the disclosure of sensitive data, such as environment configuration files that often contain database credentials, API keys, or other confidential information, as well as critical system files. This poses a significant risk for data breaches and further system compromise.

## Attack Chain

1. Attacker identifies a vulnerable Microweber CMS instance (version 2.0.20 or earlier).
2. Attacker crafts a malicious HTTP GET request targeting a web endpoint associated with the static file controller.
3. The request includes a specially crafted `path` query parameter containing directory traversal sequences (e.g., `../../`) to navigate outside the intended directory.
4. The vulnerable `normalize_path()` function within the CMS fails to properly remove these traversal sequences.
5. The server processes the request, mistakenly resolving the path to an arbitrary file on the underlying operating system.
6. The web server retrieves the content of the specified arbitrary file, such as `/etc/passwd`, `/etc/shadow`, or environment configuration files (`.env`).
7. The server includes the sensitive file's content in the HTTP response body to the attacker.
8. The attacker successfully exfiltrates sensitive information, potentially leading to credential compromise or further system access.

## Impact

Successful exploitation of CVE-2026-65694 allows unauthenticated attackers to read any file accessible to the web server process. This directly leads to the disclosure of sensitive information such as database credentials, API keys, private configuration data, and system files. The impact could range from unauthorized access to sensitive application data to full system compromise if credentials for higher-privileged services are exposed. While no specific victim count or sectors are mentioned, any organization utilizing Microweber CMS versions affected by this vulnerability is at risk. Data breaches, intellectual property theft, and subsequent lateral movement or persistent access are potential consequences.

## Recommendation

* Patch CVE-2026-65694 immediately by upgrading Microweber CMS to a version beyond 2.0.20 that addresses this vulnerability.
* Deploy the Sigma rule "Detects CVE-2026-65694 Exploitation - Microweber Path Traversal" to your SIEM to identify attempted exploitation.
* Ensure web server logs (logsource category `webserver`) are collected and ingested into your SIEM for effective detection.
* Implement web application firewall (WAF) rules to block HTTP GET requests containing directory traversal sequences (`../`, `%2e%2e%2f`, etc.) in query parameters, particularly those associated with static file handlers.
