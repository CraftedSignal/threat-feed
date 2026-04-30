---
title: Glances XML-RPC Server Cross-Origin Information Disclosure
slug: 2026-05-glances-xmlrpc-cors
description: The Glances XML-RPC server exposes sensitive system information due to a permissive CORS policy and missing Content-Type validation, enabling attackers to bypass CORS restrictions and steal data like hostnames, OS details, IP addresses, and process lists.
date: "2026-03-30T17:01:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - glances
  - cors
  - information-disclosure
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1213
    technique_name: Data from Information Repository
references:
  - https://github.com/advisories/GHSA-7p93-6934-f4q7
iocs:
  - type: url
    value: http://evil-attacker.com
  - type: url
    value: http://TARGET_IP:61209/RPC2
ioc_counts:
  url: 2
rules:
  - title: Detect Glances XML-RPC getAll Request
    description: Detects requests to the Glances XML-RPC endpoint with the getAll method, indicating potential exploitation of the CORS vulnerability.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Glances XML-RPC Text Plain POST
    description: Detects POST requests with Content-Type text/plain to the Glances XML-RPC endpoint, indicative of a CORS bypass attempt.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Glances system monitoring tool, when run in server mode using the XML-RPC interface (initiated with `glances -s` or `glances --server`), is vulnerable to a cross-origin information disclosure. This vulnerability exists because the XML-RPC server sends the `Access-Control-Allow-Origin: *` header on every HTTP response without validating the `Content-Type` header. An attacker can exploit this by crafting a CORS "simple request" (a POST request with `Content-Type: text/plain`) containing a valid XML-RPC payload.  Because browsers do not send a preflight OPTIONS request for simple requests, the attacker can bypass CORS protections and retrieve sensitive data. This affects Glances versions up to and including 4.5.1.  The separate REST API was patched in 4.5.1 (CVE-2026-32610), but the XML-RPC component remains vulnerable (CVE-2026-33533).

## Attack Chain

1. The attacker identifies a target running Glances in XML-RPC server mode, typically on port 61209 (`glances -s -p 61209`).
2. The attacker crafts a malicious webpage containing JavaScript code to send a POST request to the Glances XML-RPC endpoint (`/RPC2`).
3. The POST request includes an XML-RPC payload within the body (e.g., `<?xml version="1.0"?><methodCall><methodName>getAll</methodName></methodCall>`).
4. The request is sent with the `Content-Type` header set to `text/plain` to qualify as a CORS "simple request," bypassing the need for a preflight OPTIONS request.
5. The Glances XML-RPC server processes the request regardless of the `Content-Type` due to missing validation in `GlancesXMLRPCHandler.send_my_headers` in `server.py`.
6. The server responds with the requested system monitoring data and includes the `Access-Control-Allow-Origin: *` header.
7. The attacker's JavaScript code parses the XML response and extracts the sensitive system information, including hostname, OS version, IP addresses, CPU/memory/disk/network stats, and the full process list with command lines.
8.  The attacker exfiltrates the stolen data to a remote server or displays it within the malicious webpage.

## Impact

Successful exploitation allows an attacker to steal sensitive system information from any Glances instance running in server mode without authentication.  This includes hostname, OS version, IP addresses, CPU/memory/disk/network statistics, and a full process list, which can expose sensitive credentials or internal paths contained within command-line arguments.  The default configuration for Glances has no authentication enabled, making all instances vulnerable out-of-the-box, impacting any user running Glances in server mode on a network-accessible interface.

## Recommendation

*   Disable the Glances XML-RPC server (`glances -s`) if it's not required, as this is the root cause of the vulnerability.
*   Deploy the Sigma rule `Detect Glances XML-RPC getAll Request` to detect exploitation attempts against the XML-RPC endpoint.
*   Monitor network traffic for POST requests with `Content-Type: text/plain` to the `/RPC2` endpoint of Glances servers, using the IOC `url: http://TARGET_IP:61209/RPC2`.
*   Upgrade Glances to a patched version that addresses CVE-2026-33533 when a patch becomes available. Currently, the provided source indicates no patch exists even in the latest dev branch.
