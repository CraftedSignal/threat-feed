---
title: LORIS File Traversal Vulnerability (CVE-2026-34392)
slug: 2026-04-loris-file-traversal
description: A file traversal vulnerability (CVE-2026-34392) in LORIS versions 20.0.0 to before 27.0.3 and 28.0.1 allows an unauthenticated attacker to download arbitrary files via the static file router.
date: "2026-04-08T19:25:21Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - file-traversal
  - web-application
  - cve-2026-34392
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34392
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34392
  - https://github.com/aces/Loris/security/advisories/GHSA-rfj5-58hv-wc5f
rules:
  - title: LORIS File Traversal Attempt via Static Endpoints
    description: Detects attempts to exploit CVE-2026-34392 by using directory traversal sequences in requests to LORIS static file endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: LORIS File Traversal via Encoded Traversal Sequences
    description: Detects attempts to exploit CVE-2026-34392 using URL encoded directory traversal sequences.
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

LORIS (Longitudinal Online Research and Imaging System) is a self-hosted web application used for data and project management in neuroimaging research. A critical file traversal vulnerability, identified as CVE-2026-34392, exists within the static file router of LORIS versions 20.0.0 to before 27.0.3 and 28.0.1. This flaw allows an unauthenticated attacker to access and download unintended files by manipulating requests to the `/static`, `/css`, and `/js` endpoints. Successful exploitation of this vulnerability can lead to the exposure of sensitive data, including configuration files, source code, and potentially patient information. The vulnerability is patched in versions 27.0.3 and 28.0.1. Organizations using vulnerable versions of LORIS should upgrade immediately.

## Attack Chain

1.  The attacker identifies a LORIS instance running a vulnerable version (20.0.0 to before 27.0.3 or 28.0.1).
2.  The attacker crafts a malicious HTTP request targeting the `/static`, `/css`, or `/js` endpoints.
3.  The crafted request includes a file traversal sequence (e.g., `../`) in the URL to navigate outside the intended directory.
4.  The LORIS static file router improperly handles the traversal sequence, failing to sanitize the requested path.
5.  The webserver retrieves the file specified by the attacker, potentially including sensitive configuration files or source code.
6.  The webserver responds with the contents of the requested file, which may contain sensitive information.
7.  The attacker downloads the file and analyzes its contents for valuable information, such as database credentials or API keys.

## Impact

Successful exploitation of CVE-2026-34392 can have severe consequences. An attacker can gain unauthorized access to sensitive files within the LORIS application. This can lead to the exposure of configuration files containing database credentials, API keys, or other sensitive data. The exposure of source code could also facilitate the discovery of other vulnerabilities. Depending on the files exposed, this could lead to further compromise of the LORIS system and potentially the underlying infrastructure, impacting the confidentiality and integrity of the research data managed by the system.

## Recommendation

*   Upgrade LORIS to version 27.0.3 or 28.0.1 or later to patch CVE-2026-34392.
*   Implement web application firewall (WAF) rules to detect and block requests containing directory traversal sequences targeting the `/static`, `/css`, and `/js` endpoints.
*   Deploy the Sigma rules provided to detect exploitation attempts in web server logs.
