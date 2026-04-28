---
title: CrowdStrike LogScale Unauthenticated Path Traversal Vulnerability (CVE-2026-40050)
slug: 2026-04-crowdstrike-logscale-path-traversal
description: A critical unauthenticated path traversal vulnerability (CVE-2026-40050) in CrowdStrike LogScale allows remote attackers to read arbitrary files from the server filesystem if a specific cluster API endpoint is exposed, necessitating immediate patching for self-hosted customers.
date: "2026-04-22T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - path-traversal
  - vulnerability
  - logscale
  - crowdstrike
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40050
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40050
rules:
  - title: Detect LogScale Path Traversal Attempts
    description: Detects potential path traversal attempts against LogScale servers by monitoring HTTP requests with common path traversal sequences.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect LogScale HTTP 400 Errors Indicative of Exploitation
    description: Detects HTTP 400 errors from LogScale servers when processing suspicious path traversal payloads
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CrowdStrike has disclosed CVE-2026-40050, a critical unauthenticated path traversal vulnerability affecting specific versions of LogScale. This vulnerability allows unauthenticated remote attackers to read arbitrary files from the server's filesystem. The vulnerability resides in a specific cluster API endpoint. CrowdStrike mitigated the vulnerability for LogScale SaaS customers on April 7, 2026, by deploying network-layer blocks. CrowdStrike self-hosted LogScale customers are urged to upgrade to a patched version immediately to remediate the vulnerability. The vulnerability was identified through CrowdStrike's internal product testing. Next-Gen SIEM customers are not affected.

## Attack Chain

1.  Attacker identifies a vulnerable LogScale instance with the exposed cluster API endpoint.
2.  Attacker crafts a malicious HTTP request containing a path traversal payload targeting the vulnerable API endpoint.
3.  The crafted request bypasses authentication checks due to the vulnerability.
4.  LogScale server processes the request and attempts to access the file specified in the path traversal payload.
5.  Due to the missing input validation, the server accesses files outside the intended directory.
6.  The server reads the contents of the targeted file from the filesystem.
7.  The file content is included in the HTTP response sent back to the attacker.
8.  Attacker obtains sensitive information from the server's filesystem, such as configuration files, credentials, or internal data.

## Impact

Successful exploitation of CVE-2026-40050 allows an unauthenticated remote attacker to read arbitrary files on the LogScale server. This could lead to the exposure of sensitive data, including configuration files, credentials, and internal application data. The vulnerability affects self-hosted LogScale customers who have not applied the necessary security updates. The impact could be severe, potentially leading to data breaches or unauthorized access to the system.

## Recommendation

*   Upgrade self-hosted LogScale instances to the latest patched version to remediate CVE-2026-40050 immediately.
*   Monitor web server logs for suspicious requests containing path traversal patterns targeting LogScale's API endpoints to detect potential exploitation attempts (see rule: "Detect LogScale Path Traversal Attempts").
*   Deploy network-layer blocks to restrict access to the vulnerable API endpoint if immediate patching is not feasible.
*   Review access controls and network segmentation to limit the impact of potential future vulnerabilities.
*   Enable webserver logging to capture cs-uri-query, cs-uri-stem, and cs-method to improve visibility and incident response.
