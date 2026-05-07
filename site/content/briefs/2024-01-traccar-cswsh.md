---
title: Traccar GPS Tracking System 6.11.1 Cross-Site WebSocket Hijacking
slug: 2024-01-traccar-cswsh
description: Traccar GPS Tracking System 6.11.1 is vulnerable to Cross-Site WebSocket Hijacking (CSWSH), enabling attackers to steal sensitive GPS data by exploiting a lack of origin validation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cswsh
  - websocket
  - gps
  - infostealer
vendors:
  - traccar
products:
  - Traccar GPS Tracking System <= 6.11.1
affected_os:
  - Windows 11
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2025-68930
    cvss: 7.1
    epss: 0.00112
references:
  - https://www.exploit-db.com/exploits/52545
rules:
  - title: Detect Suspicious Traccar WebSocket Connection with Malicious Origin
    description: Detects Traccar WebSocket connections with a suspicious Origin header, indicating potential CSWSH exploitation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Traccar WebSocket Connection with Missing Origin Header
    description: Detects Traccar WebSocket connections with a missing Origin header, which can also be indicative of CSWSH attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Traccar GPS Tracking System, a widely used application for tracking GPS devices, is vulnerable to Cross-Site WebSocket Hijacking (CSWSH) in version 6.11.1 and earlier. Discovered in February 2026, this vulnerability stems from the application's failure to properly validate the `Origin` header during WebSocket connections established via the `/api/socket` endpoint. An attacker can exploit this flaw to bypass the Same Origin Policy (SOP) by injecting a malicious `Origin` header alongside a valid `JSESSIONID` of a victim user. Successful exploitation allows the attacker to hijack the WebSocket connection and gain unauthorized access to real-time sensitive data, specifically GPS coordinates and device status information. This poses a significant risk to organizations relying on Traccar for secure location tracking, potentially exposing sensitive location data to unauthorized parties.

## Attack Chain

1.  Attacker identifies a vulnerable Traccar GPS Tracking System instance running version 6.11.1 or earlier.
2.  Attacker obtains a valid `JSESSIONID` cookie from a legitimate user of the Traccar application, potentially through social engineering or session riding.
3.  Attacker crafts a malicious webpage with JavaScript code to establish a WebSocket connection to the vulnerable `/api/socket` endpoint.
4.  The malicious webpage sets the `Origin` header to an attacker-controlled domain (e.g., `http://hacker.com`) and includes the stolen `JSESSIONID` cookie in the request headers.
5.  The Traccar server, failing to validate the `Origin` header, accepts the WebSocket connection from the attacker's webpage.
6.  The attacker's WebSocket connection now acts as a proxy, receiving real-time data intended for the legitimate user, including GPS coordinates and device status updates.
7.  The attacker logs and analyzes the streamed data, extracting sensitive information such as device locations, routes, and operational status.
8.  The attacker can use the stolen GPS data for malicious purposes, such as tracking assets, identifying patterns of movement, or conducting surveillance.

## Impact

Successful exploitation of this CSWSH vulnerability can result in the leakage of highly sensitive real-time GPS data, including precise location coordinates and device status information. The impact can be significant for organizations using Traccar to track valuable assets, monitor employee movements, or manage logistics. A successful attack could expose sensitive operational details, compromise physical security, and enable unauthorized tracking of individuals or vehicles. While the number of affected installations is unknown, any organization using Traccar GPS Tracking System version 6.11.1 or earlier is potentially at risk.

## Recommendation

*   Upgrade Traccar GPS Tracking System to a version that addresses CVE-2025-68930 to prevent Cross-Site WebSocket Hijacking.
*   Implement and enforce strict `Origin` header validation on the WebSocket endpoint `/api/socket` to prevent unauthorized connections.
*   Deploy the provided Sigma rule to detect suspicious WebSocket connections originating from unexpected domains.
*   Monitor network traffic for connections to the `/api/socket` endpoint with unusual `Origin` headers, as indicated in the attack chain.
