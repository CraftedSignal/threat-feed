---
title: FileBrowser Quantum Unauthenticated Information Disclosure Vulnerability
slug: 2026-05-filebrowser-info-disclosure
description: FileBrowser Quantum is susceptible to CVE-2026-46410, an unauthenticated information disclosure vulnerability, potentially exposing sensitive information such as source code and file paths.
date: "2026-05-19T20:15:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - web-application
  - github
vendors:
  - GitHub
products:
  - filebrowser
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
references:
  - https://github.com/advisories/GHSA-3jmg-p96m-m328
  - CVE-2026-46410
rules:
  - title: Detects CVE-2026-46410 exploitation - FileBrowser Information Disclosure Attempt
    description: Detects attempts to exploit CVE-2026-46410 by identifying suspicious URI patterns that could lead to information disclosure in FileBrowser.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - webserver
  - title: Detects CVE-2026-46410 exploitation - FileBrowser Sensitive File Request
    description: Detects CVE-2026-46410 exploitation — Monitors web server logs for requests to configuration files within FileBrowser Quantum that should not be publicly accessible.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - webserver
rules_count: 2
---

FileBrowser Quantum, a web-based file manager, contains an information disclosure vulnerability (CVE-2026-46410) that can expose sensitive information to unauthorized users. This vulnerability affects versions prior to 1.2.1-stable.0.20260514154726-1802e1281135 and backend versions prior to 0.0.0-20260514154726-1802e1281135. An unauthenticated attacker can potentially access file paths and source code. This vulnerability can be exploited remotely due to a low attack complexity and no required user interaction. Defenders need to ensure their FileBrowser Quantum instances are up to date to prevent unauthorized information disclosure.

## Attack Chain

1.  An unauthenticated attacker identifies a FileBrowser Quantum instance running a vulnerable version.
2.  The attacker crafts a specific HTTP request to a vulnerable endpoint.
3.  FileBrowser processes the request without proper authorization checks.
4.  The application retrieves sensitive file information (source code, paths).
5.  This information is unintentionally included in the HTTP response.
6.  The attacker parses the response to extract sensitive data.
7.  The attacker uses the disclosed information to gain further insights into the system's configuration and potentially identify other vulnerabilities.
8.  The attacker uses the information for lateral movement or further exploitation.

## Impact

Successful exploitation of CVE-2026-46410 allows an unauthenticated attacker to gain access to sensitive information, such as file paths and source code. This information can be leveraged to understand the system's internal structure, identify other vulnerabilities, and potentially gain unauthorized access to sensitive files. The lack of integrity and availability impact metrics suggests the primary risk is related to data leakage rather than system disruption.

## Recommendation

*   Upgrade FileBrowser Quantum to the latest version to patch CVE-2026-46410.
*   Implement the provided Sigma rule to detect suspicious requests targeting potential information disclosure endpoints.
*   Monitor web server logs for unusual URI requests that could indicate exploitation attempts.
