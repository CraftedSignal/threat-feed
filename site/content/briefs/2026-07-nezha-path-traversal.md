---
title: Nezha Monitoring Pre-Auth Path Traversal via Dashboard Prefix Confusion (CVE-2026-53519)
slug: 2026-07-nezha-path-traversal
description: A critical pre-authentication path traversal vulnerability, CVE-2026-53519, in Nezha Monitoring's dashboard allows an unauthenticated attacker to read arbitrary files from the server's working directory, leading to the exfiltration of the `jwt_secret_key` and full administrative account takeover.
date: "2026-07-03T10:22:16Z"
lastmod: "2026-09-10T09:11:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:nezhahq:nezha_monitoring:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=BC1616F3-5603-5DF0-BC03-2E01A7A1107D&utm_source=rss&utm_medium=rss
tags:
  - path-traversal
  - unauthenticated
  - webserver
  - credential-access
  - privilege-escalation
  - nezha-monitoring
  - cve
vendors:
  - nezhahq
products:
  - Nezha Monitoring (< 2.0.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A pre-authentication path traversal vulnerability in Nezha Monitoring's dashboard allows an unauthenticated attacker to read arbitrary files from the server's working directory.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: read arbitrary files from the server's working directory... `sqlite.db`, which holds user data including admin IDs.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: attackers can exfiltrate sensitive files like `config.yaml`, which contains the `jwt_secret_key`.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: With the `jwt_secret_key`, an attacker can forge administrative session cookies, leading to full administrative account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-53519
    cvss: 9.1
    epss: 0.01928
references:
  - https://github.com/advisories/GHSA-5c25-7vpj-9mqh
  - https://sploitus.com/exploit?id=BC1616F3-5603-5DF0-BC03-2E01A7A1107D&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-53519 Exploitation - Nezha Monitoring Path Traversal
    description: Detects unauthenticated path traversal attempts in Nezha Monitoring (CVE-2026-53519) via dashboard prefix confusion to access sensitive files like config.yaml or sqlite.db.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-09-10T09:11:42Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=BC1616F3-5603-5DF0-BC03-2E01A7A1107D&utm_source=rss&utm_medium=rss
---

A severe pre-authentication path traversal vulnerability (CVE-2026-53519) has been discovered in Nezha Monitoring, affecting versions prior to 2.0.13. The flaw stems from a prefix confusion in the dashboard's `NoRoute` handler, where the `fallbackToFrontend` function incorrectly processes URLs starting with `/dashboard`. By exploiting `strings.HasPrefix` and `path.Join` combined with Go's `http.ServeFile` behavior, an unauthenticated attacker can craft a malicious URL like `/dashboard../data/config.yaml` to bypass intended security checks and access sensitive files outside the `/admin-dist` directory. This allows for the exfiltration of critical data, most notably `data/config.yaml`, which contains the `jwt_secret_key`, and `data/sqlite.db`, which holds user account information. Possession of the `jwt_secret_key` enables the attacker to forge administrative JSON Web Tokens (JWTs), leading to full administrative account takeover of the Nezha Monitoring instance.

## Attack Chain

1.  An unauthenticated attacker sends an HTTP GET request to a crafted URL like `/dashboard../data/config.yaml`, targeting the Nezha Monitoring dashboard.
2.  The vulnerable `fallbackToFrontend` handler's `strings.HasPrefix` check incorrectly matches `/dashboard..`, and `strings.TrimPrefix` leaves `../data/config.yaml`.
3.  `path.Join("admin-dist", "../data/config.yaml")` normalizes the path to `data/config.yaml`, causing `os.Stat` to locate the sensitive file.
4.  Go's `http.ServeFile` serves the `data/config.yaml` file to the attacker, bypassing its internal `..`-segment guard due to the non-canonical `/dashboard..` segment.
5.  The attacker extracts the `jwt_secret_key` from the exfiltrated `config.yaml` and repeats the process to exfiltrate `data/sqlite.db`, identifying administrative user IDs.
6.  Using the `jwt_secret_key` and an administrative user ID, the attacker forges a valid HS256-signed JWT for an administrator account.
7.  The attacker uses the forged JWT as a session cookie or Bearer token to gain full administrative access to the Nezha Monitoring dashboard, enabling actions like server management, user creation/deletion, and notification configuration.

## Impact

Successful exploitation of CVE-2026-53519 grants an unauthenticated attacker the ability to read any file within the dashboard's working directory subtree, provided it is one level up from `admin-dist`. In default deployments, this includes `data/config.yaml`, which contains sensitive secrets such as the `jwt_secret_key`, `agent_secret_key`, OAuth2 client secrets, and GeoIP API keys. Additionally, `data/sqlite.db` can be exfiltrated, revealing the full dashboard state including all users (and their bcrypt password hashes), server registries, and API tokens. The primary impact is immediate administrative account takeover, allowing the attacker to fully control the Nezha Monitoring instance, potentially leading to data manipulation, unauthorized monitoring, or further compromise of integrated systems.

## Recommendation

*   Immediately update Nezha Monitoring to version 2.0.13 or newer to patch CVE-2026-53519.
*   Deploy the provided Sigma rule to your SIEM to detect and alert on attempts to exploit CVE-2026-53519.
*   Implement Web Application Firewall (WAF) rules to block HTTP GET requests containing the `/dashboard../data/config.yaml` and `/dashboard../data/sqlite.db` patterns, including their URL-encoded variants listed in the IOCs.
*   Review access logs for the IOC URLs prior to patching to identify potential exploitation attempts.
