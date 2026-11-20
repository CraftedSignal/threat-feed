---
brief_id: brief-2024-01-03-mathjs-rce
event_id: brief-2024-01-03-mathjs-rce
revision: 1
activity_at: "2024-01-03T15:00:00Z"
title: Math.js Expression Parser Remote Code Execution Vulnerability
slug: 2024-01-mathjs-rce
description: A remote code execution vulnerability exists in the mathjs library versions 13.1.1 before 15.2.0, enabling arbitrary JavaScript execution via the expression parser when processing user-supplied expressions.
date: "2024-01-03T15:00:00Z"
lastmod: "2026-11-20T03:04:06Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:mathjs:mathjs:*:*:*:*:*:node.js:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-YYM8538-CVE-2026-40897&utm_source=rss&utm_medium=rss
tags:
  - mathjs
  - rce
  - javascript
vendors:
  - Mathjs
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
cve_verification:
  CVE-2026-40897:
    status: verified
    source: nvd
    checked_at: 2026-11-20T03:04:06.203881455Z
cves:
  - id: CVE-2026-40897
    cvss: 8.8
    epss: 0.00591
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-29qv-4j9f-fjw5
  - https://github.com/josdejong/mathjs/commit/513ab2a0e01004af91b31aada68fae8a821326ad
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-YYM8538-CVE-2026-40897&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Attempts to Exploit Math.js RCE via Web Logs
    description: Detects attempts to exploit the Math.js RCE vulnerability by monitoring for suspicious patterns in HTTP request URIs.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Use of Math.js in Process Creation
    description: Detects potential exploitation of Math.js by monitoring for suspicious process creation events involving node.js and potentially malicious arguments.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Math.js RCE via Process Command Line
    description: Detects potential RCE attempts by monitoring for suspicious command-line arguments related to math.js.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 3
updates:
  - at: "2026-11-20T03:04:06Z"
    level: L2
    summary: poc_available; added CVE-2026-40897
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-YYM8538-CVE-2026-40897&utm_source=rss&utm_medium=rss
---

## Overview

The mathjs library, a popular JavaScript library for mathematical operations, contains a remote code execution vulnerability (CVE-2026-40897) affecting versions v13.1.1 up to v15.2.0. This flaw allows an attacker to execute arbitrary JavaScript code by crafting malicious expressions that are processed by the library's expression parser. The vulnerability arises due to an unsafe object property setter. Applications that utilize mathjs to evaluate user-supplied mathematical expressions are particularly vulnerable. This issue was resolved with the release of mathjs version 15.2.0. Defenders need to identify and update vulnerable instances of the library immediately to prevent potential exploitation.

## Attack Chain

1. An attacker identifies an application using a vulnerable version of mathjs (v13.1.1 - v15.1.x).
2. The attacker crafts a malicious mathematical expression designed to exploit the unsafe object property setter vulnerability.
3. The attacker inputs this expression into the application's mathjs evaluation function.
4. Mathjs parses the malicious expression.
5. The unsafe object property setter allows the attacker to inject arbitrary JavaScript code during the parsing process.
6. The injected JavaScript code executes within the context of the application server.
7. The attacker gains remote code execution, potentially allowing them to read sensitive data, modify application logic, or compromise the underlying system.

## Impact

Successful exploitation of this vulnerability allows for arbitrary JavaScript execution within the context of the application using the vulnerable mathjs library. This could lead to complete compromise of the application, including unauthorized data access, modification, or denial of service. The scope of impact depends on the privileges of the application and the environment in which it operates. This vulnerability is present in mathjs versions 13.1.1 to versions before 15.2.0.

## Recommendation

*   Upgrade mathjs to version 15.2.0 or later to patch the vulnerability (CVE-2026-40897).
*   Examine application logs from web servers for unusual activity related to mathjs processing.
*   Implement input validation and sanitization on user-supplied mathematical expressions before they are processed by mathjs.
*   Monitor the integrity of the mathjs library files to detect unauthorized modifications.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts against the mathjs library.
