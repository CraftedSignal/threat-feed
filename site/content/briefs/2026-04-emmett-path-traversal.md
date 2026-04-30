---
title: Emmett Web Framework Path Traversal Vulnerability (CVE-2026-39847)
slug: 2026-04-emmett-path-traversal
description: Emmett web framework versions 2.5.0 to before 2.8.1 are vulnerable to path traversal attacks (CVE-2026-39847), allowing attackers to read arbitrary files outside the intended assets directory using manipulated URLs.
date: "2026-04-07T22:16:23Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - web-application
  - emmett
  - cve-2026-39847
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-39847
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39847
  - https://github.com/emmett-framework/emmett/security/advisories/GHSA-pr46-2v3c-5356
rules:
  - title: Detect Emmett Path Traversal Attempts
    description: Detects path traversal attempts targeting the /__emmett__/ path in Emmett web framework.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Deep Path Traversal in Emmett Web Framework
    description: This rule detects potential deep path traversal attempts within the /__emmett__/ directory, specifically looking for multiple instances of '../' to identify unusual access patterns.
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

The Emmett web framework, a full-stack Python framework, is susceptible to a path traversal vulnerability affecting versions 2.5.0 to prior to 2.8.1. Specifically, the RSGI static handler for Emmett's internal assets (/__emmett__ paths) does not properly sanitize user-supplied input, leading to CVE-2026-39847. By crafting malicious URLs containing "../" sequences, an unauthenticated attacker can bypass directory restrictions and access sensitive files residing outside the designated assets directory. Successful exploitation allows attackers to potentially read application source code, configuration files, or other sensitive data. Emmett users are urged to upgrade to version 2.8.1 or later to remediate this vulnerability. The vulnerability was reported on April 7th, 2026.

## Attack Chain

1.  The attacker identifies a vulnerable Emmett web application running a version between 2.5.0 and 2.8.1.
2.  The attacker crafts a malicious HTTP GET request targeting a static asset under the `/__emmett__` path.
3.  The crafted URL includes "../" sequences to traverse up the directory structure from the intended assets directory. For example: `/__emmett__/../../../../etc/passwd`.
4.  The web server receives the request and passes it to the vulnerable RSGI static handler.
5.  Due to the lack of input sanitization, the handler processes the "../" sequences, allowing the attacker to navigate outside the assets directory.
6.  The handler attempts to read the file specified in the manipulated path (e.g., `/etc/passwd`).
7.  The server returns the contents of the requested file in the HTTP response.
8.  The attacker obtains sensitive information from the server, potentially including configuration files, source code, or credentials.

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-39847) allows an attacker to read arbitrary files on the server hosting the Emmett web application. This can lead to the exposure of sensitive information such as application source code, configuration files containing database credentials, or even system files. The impact can range from information disclosure to complete compromise of the web application and potentially the underlying server. The severity is rated as critical with a CVSS v3.1 score of 9.1.

## Recommendation

*   Upgrade Emmett to version 2.8.1 or later to patch CVE-2026-39847.
*   Deploy the Sigma rule "Detect Emmett Path Traversal Attempts" to your SIEM to identify exploitation attempts.
*   Monitor web server logs for suspicious URLs containing "../" sequences targeting the `/__emmett__` path to identify potential exploit attempts.
*   Implement web application firewall (WAF) rules to block requests containing path traversal sequences.
