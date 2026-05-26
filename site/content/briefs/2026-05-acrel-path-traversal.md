---
title: Acrel EEMS Enterprise Power Operation and Maintenance Cloud Platform Path Traversal Vulnerability (CVE-2026-9550)
slug: 2026-05-acrel-path-traversal
description: A path traversal vulnerability (CVE-2026-9550) exists in Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform 1.3.0, allowing remote attackers to access sensitive files by manipulating the path argument in the /SubstationWEBV2/app/..;/main/upfile component.
date: "2026-05-26T15:21:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve
vendors:
  - Acrel Electrical
products:
  - EEMS Enterprise Power Operation and Maintenance Cloud Platform 1.3.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9550
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9550
  - CVE-2026-9550
rules:
  - title: Detects CVE-2026-9550 Exploitation — Path Traversal in Acrel EEMS upfile
    description: Detects CVE-2026-9550 exploitation — HTTP requests to /SubstationWEBV2/app/..;/main/upfile with path traversal sequences in the URI indicating a path traversal attempt
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-9550 Exploitation — Attempted Path Traversal via URL Encoding
    description: Detects CVE-2026-9550 exploitation - Attempts to use URL encoding to bypass path traversal restrictions in Acrel EEMS upfile
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-9550, affects Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform version 1.3.0. The vulnerability resides in the `/SubstationWEBV2/app/..;/main/upfile` functionality, where manipulation of the `path` argument can lead to unauthorized file access. This issue allows remote attackers to potentially read sensitive files or execute arbitrary code. Public exploitation details are available, increasing the risk of widespread attacks. The vendor was contacted regarding the vulnerability but did not respond. Due to the ease of exploitation and potential for significant impact, defenders should prioritize patching or mitigating this vulnerability.

## Attack Chain

1. An attacker identifies a vulnerable Acrel EEMS Enterprise Power Operation and Maintenance Cloud Platform instance running version 1.3.0.
2. The attacker crafts a malicious HTTP request targeting the `/SubstationWEBV2/app/..;/main/upfile` endpoint.
3. The attacker manipulates the `path` parameter within the request to include path traversal sequences (e.g., `../`) to navigate the file system.
4. The application incorrectly processes the manipulated path, allowing the attacker to access files outside the intended directory.
5. The attacker retrieves sensitive files, such as configuration files or credentials.
6. The attacker uses the gathered information to escalate privileges or gain further access to the system.
7. The attacker may deploy malicious code to compromise the platform or connected systems.
8. The attacker achieves full system compromise, allowing them to steal data, disrupt operations, or pivot to other internal systems.

## Impact

Successful exploitation of CVE-2026-9550 can lead to unauthorized access to sensitive information, potentially including configuration files, credentials, and proprietary data. This could result in data breaches, system compromise, and disruption of power operation and maintenance services. The lack of vendor response and public availability of exploit details significantly increases the risk of widespread exploitation.

## Recommendation

*   Apply any available patches or updates from Acrel Electrical to address CVE-2026-9550. Since the vendor has not responded, consider alternative mitigation strategies.
*   Implement input validation and sanitization on the `path` parameter to prevent path traversal attacks.
*   Deploy the Sigma rules provided below to detect exploitation attempts targeting the `/SubstationWEBV2/app/..;/main/upfile` endpoint and path traversal sequences.
*   Monitor web server logs for suspicious requests containing path traversal characters (e.g., `../`, `..%2f`) in the URI.
*   Implement network segmentation to limit the impact of a successful compromise.
