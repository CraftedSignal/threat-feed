---
brief_id: brief-2024-01-02-forticlientems-rce
event_id: brief-2024-01-02-forticlientems-rce
revision: 1
activity_at: "2024-01-02T12:00:00Z"
title: Fortinet FortiClientEMS Unauthenticated Remote Code Execution Vulnerability (CVE-2026-35616)
slug: 2024-01-forticlientems-rce
description: An unauthenticated attacker can exploit an improper access control vulnerability (CVE-2026-35616) in Fortinet FortiClientEMS 7.4.5 through 7.4.6 via crafted requests, leading to remote code execution.
date: "2024-01-02T12:00:00Z"
lastmod: "2026-11-20T01:36:50Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-04-06T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:fortinet:forticlientems:7.4.5:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:forticlientems:7.4.6:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=AD38BB37-3025-5A90-8BE4-E526D0909F1C&utm_source=rss&utm_medium=rss
tags:
  - fortinet
  - forticlientems
  - rce
  - cve-2026-35616
vendors:
  - Fortinet
products:
  - FortiClient EMS
  - Forticlientems
  - FortiGate
product_versions:
  - product: Forticlientems
    range: 7.4.5
  - product: Forticlientems
    range: 7.4.6
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35616
    cvss: 9.8
    epss: 0.4117
    kev: true
    kev_status: "true"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35616
  - https://www.securityweek.com/critical-forticlient-ems-vulnerability-exploited-in-fresh-attacks/
  - https://www.bleepingcomputer.com/news/security/hackers-exploit-forticlient-ems-flaw-to-push-infostealer-malware/
  - https://sploitus.com/exploit?id=AD38BB37-3025-5A90-8BE4-E526D0909F1C&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=AD38BB37-3025-5A90-8BE4-E526D0909F1C&utm_source=rss&utm_medium=rss
  - type: url
    value: https://tinyurl.com/255fbm7z
ioc_counts:
  url: 2
rules:
  - title: Detect Potential FortiClientEMS Exploitation via HTTP Request
    description: Detects suspicious HTTP requests potentially exploiting CVE-2026-35616
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious FortiClientEMS HTTP Response Codes
    description: Detects unexpected server response codes that may indicate an attempted exploit
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-05-28T12:56:59Z"
    level: L1
    summary: new product
    sources:
      - securityweek
  - at: "2026-05-28T17:25:59Z"
    level: L1
    summary: new IOCs
    sources:
      - bleepingcomputer
  - at: "2026-05-31T16:01:49Z"
    level: L2
    summary: poc_available; added CVE-2026-35616
    sources:
      - sploitus
  - at: "2026-11-20T01:36:50Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-35616
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

CVE-2026-35616 is a critical vulnerability affecting Fortinet FortiClientEMS (Enterprise Management Server) versions 7.4.5 through 7.4.6. This improper access control flaw allows an unauthenticated attacker to send specially crafted requests to the server. Successful exploitation could lead to arbitrary code execution on the affected system. FortiClientEMS is used to centrally manage and deploy FortiClient endpoint security software, making it a valuable target. Given the sensitive nature of EMS, a successful attack can compromise numerous endpoints managed by the server. Defenders should prioritize patching and implementing detection measures.

## Attack Chain

1.  The attacker identifies a vulnerable FortiClientEMS server running versions 7.4.5 or 7.4.6.
2.  The attacker crafts a malicious HTTP request designed to exploit the improper access control vulnerability. This request likely targets a specific API endpoint.
3.  The attacker sends the crafted request to the FortiClientEMS server.
4.  The server fails to properly authenticate or authorize the request due to the access control vulnerability.
5.  The server processes the malicious request, leading to execution of unauthorized code or commands.
6.  The attacker gains initial access to the FortiClientEMS server with the privileges of the EMS process.
7.  The attacker leverages the compromised EMS server to deploy malicious payloads to managed FortiClient endpoints.
8.  The attacker achieves widespread compromise of the environment through the managed endpoint infrastructure.

## Impact

Successful exploitation of CVE-2026-35616 allows an unauthenticated attacker to execute arbitrary code on the FortiClientEMS server. This can lead to a full compromise of the server and the potential to deploy malicious software to all managed endpoints, resulting in widespread data exfiltration, ransomware deployment, or other malicious activities. Given the central role of FortiClientEMS in managing endpoint security, a successful attack has a high impact, potentially affecting hundreds or thousands of endpoints, depending on the size of the organization.

## Recommendation

*   Upgrade Fortinet FortiClientEMS to a patched version that addresses CVE-2026-35616.
*   Monitor web server logs for suspicious requests targeting FortiClientEMS (cs-uri-query, cs-method, sc-status).
*   Deploy the Sigma rule to detect potential exploitation attempts in web server logs.
