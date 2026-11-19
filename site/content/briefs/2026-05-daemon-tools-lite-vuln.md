---
brief_id: brief-2026-05-27-daemon-tools-lite-vuln
event_id: brief-2026-05-27-daemon-tools-lite-vuln
revision: 1
activity_at: "2026-05-27T17:41:33Z"
title: Daemon Tools Lite Embedded Malicious Code Vulnerability
slug: 2026-05-daemon-tools-lite-vuln
description: Daemon Tools Lite contains an unspecified vulnerability (CVE-2026-8398) that has a high impact on confidentiality, integrity, and availability, requiring immediate mitigation or discontinuation of use.
date: "2026-05-27T17:41:33Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-05-27T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:tanstack:tanstack\/arktype-adapter:1.166.12:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/arktype-adapter:1.166.15:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/eslint-plugin-router:1.161.12:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/eslint-plugin-router:1.161.9:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/eslint-plugin-start:0.0.4:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/eslint-plugin-start:0.0.7:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/history:1.161.12:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/history:1.161.9:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/nitro-v2-vite-plugin:1.154.12:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/nitro-v2-vite-plugin:1.154.15:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router-devtools:1.166.16:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router-devtools:1.166.19:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router-ssr-query:1.166.15:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router-ssr-query:1.166.18:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router:1.169.5:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-router:1.169.8:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-start-client:1.166.51:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-start-client:1.166.54:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-start:1.167.68:*:*:*:*:node.js:*:*
  - cpe:2.3:a:tanstack:tanstack\/react-start:1.167.71:*:*:*:*:node.js:*:*
tags:
  - cve-2026-8398
  - vulnerability
  - daemon tools lite
vendors:
  - Daemon
  - Daemon Tools
  - Nx
  - TanStack
products:
  - Daemon Tools Lite
  - Nx Console
  - TanStack
affected_os:
  - windows
cves:
  - id: CVE-2026-8398
    cvss: 9.8
    epss: 0.0004
    kev: true
    kev_status: "true"
  - id: CVE-2026-45321
    cvss: 9.6
    epss: 0.00027
    kev: true
    kev_status: "true"
  - id: CVE-2026-48027
    kev: true
    kev_status: "true"
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-8398
  - https://blog.daemon-tools.cc/post/security-incident
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8398
  - https://www.cisa.gov/news-events/alerts/2026/05/27/cisa-adds-three-known-exploited-vulnerabilities-catalog
rules:
  - title: Detects CVE-2026-8398 Exploitation Attempt — Daemon Tools Lite Suspicious Process
    description: Detects CVE-2026-8398 exploitation attempt — suspicious child processes spawned by Daemon Tools Lite executable.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
updates:
  - at: "2026-05-27T18:41:37Z"
    level: L2
    summary: added CVE-2026-45321 +1
    sources:
      - cisa
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-45321; KEV CVE-2026-48027; KEV CVE-2026-8398
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Daemon Tools Lite contains an unspecified vulnerability, as identified by CVE-2026-8398, which could lead to severe compromises in confidentiality, integrity, and availability of affected systems. The vulnerability requires immediate attention from system administrators to either apply vendor-supplied mitigations, adhere to BOD 22-01 guidance for cloud services if applicable, or discontinue using the software altogether. The vendor has acknowledged a security incident related to this vulnerability, prompting users to take necessary precautions to safeguard their systems and data against potential exploitation.

## Attack Chain

1. An attacker identifies vulnerable Daemon Tools Lite installations.
2. The attacker leverages CVE-2026-8398 to inject malicious code into the application.
3. The injected code executes with the privileges of the Daemon Tools Lite process.
4. The malicious code establishes a connection to a command-and-control server.
5. The attacker uses the established connection to download and execute additional payloads.
6. The payloads may include tools for lateral movement and privilege escalation.
7. The attacker gains unauthorized access to sensitive data and systems.
8. The attacker exfiltrates data or deploys ransomware, impacting confidentiality, integrity, and availability.

## Impact

Successful exploitation of CVE-2026-8398 in Daemon Tools Lite could result in significant data breaches, system compromise, and potential ransomware deployment. The impact spans confidentiality, integrity, and availability, making this a critical vulnerability requiring immediate action. Organizations using Daemon Tools Lite are at risk until mitigations are applied.

## Recommendation

*   Immediately apply mitigations as per the vendor's instructions to address CVE-2026-8398.
*   Follow applicable BOD 22-01 guidance for cloud services if using Daemon Tools Lite in a cloud environment.
*   If mitigations are unavailable, discontinue use of Daemon Tools Lite to prevent potential exploitation of CVE-2026-8398.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts.
