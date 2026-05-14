---
title: Siemens SENTRON 7KT PAC1261 Data Manager Request Smuggling Vulnerability
slug: 2026-05-siemens-sentron-request-smuggling
description: A request smuggling vulnerability exists in Siemens SENTRON 7KT PAC1261 Data Manager before V2.1.0, due to the web server improperly accepting a bare LF as a line terminator in chunked data chunk-size lines, potentially allowing an attacker to retrieve authorization tokens and gain administrative control over the device.
date: "2026-05-14T15:02:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - request-smuggling
  - cve-2025-22871
  - siemens
  - ot
vendors:
  - Siemens
products:
  - SENTRON 7KT PAC1261 Data Manager
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2025-22871
    cvss: 9.1
    epss: 0.00294
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-14
  - https://www.cve.org/CVERecord?id=CVE-2025-22871
  - https://support.industry.siemens.com/cs/ww/en/view/109977717/
rules:
  - title: Detect CVE-2025-22871 Exploitation — Siemens SENTRON Request Smuggling
    description: Detects CVE-2025-22871 exploitation — HTTP request containing a bare LF character in a chunked data chunk-size line, indicating a request smuggling attempt against Siemens SENTRON 7KT PAC1261 Data Manager
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A request smuggling vulnerability has been identified in the Siemens SENTRON 7KT PAC1261 Data Manager, specifically affecting versions prior to V2.1.0. The vulnerability, rooted in the Go Project's net/http package, stems from the improper handling of line terminators within chunked HTTP data. An attacker can exploit this flaw by sending a crafted HTTP request containing a bare line feed (LF) character where the server expects a carriage return line feed (CRLF). This inconsistency can lead to the server misinterpreting the boundaries of HTTP requests, potentially allowing the attacker to smuggle malicious requests to the backend server. Successful exploitation could allow an attacker to retrieve authorization tokens and gain administrative control over the affected device, impacting energy sector deployments worldwide.

## Attack Chain

1.  The attacker sends a specially crafted HTTP request to the SENTRON 7KT PAC1261 Data Manager with a bare LF character in a chunked data chunk-size line, instead of the expected CRLF.
2.  The vulnerable net/http package improperly parses the request, misinterpreting the boundaries between HTTP requests.
3.  The front-end server forwards the misinterpreted request to the backend server.
4.  The backend server interprets the smuggled portion of the request as a separate, legitimate request.
5.  The smuggled request targets an endpoint that returns authorization tokens or other sensitive data.
6.  The attacker captures the authorization tokens from the backend server's response.
7.  The attacker uses the stolen authorization tokens to authenticate to the SENTRON 7KT PAC1261 Data Manager as an administrator.
8.  The attacker gains administrative control over the device, potentially manipulating configurations, accessing sensitive information, or disrupting operations.

## Impact

Successful exploitation of CVE-2025-22871 can lead to unauthorized access and control over the Siemens SENTRON 7KT PAC1261 Data Manager. The vulnerability, with a CVSS v3 score of 9.1 (Critical), can allow remote unauthenticated attackers to retrieve authorization tokens and gain administrative access. Given the deployment of these devices within the energy sector worldwide, a successful attack could result in significant disruption of critical infrastructure operations, data breaches, and potential financial losses.

## Recommendation

*   Immediately update all instances of Siemens SENTRON 7KT PAC1261 Data Manager to version V2.1.0 or later to patch CVE-2025-22871.
*   As a general security measure, protect network access to devices with appropriate mechanisms as recommended by Siemens.
*   Deploy the Sigma rule "Detect CVE-2025-22871 Exploitation — Siemens SENTRON Request Smuggling" to your web server logs to identify potential exploitation attempts.
*   Minimize network exposure for all control system devices and ensure they are not accessible from the internet, as recommended by CISA.
