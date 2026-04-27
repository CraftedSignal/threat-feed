---
title: Glances XML-RPC Server Cross-Origin Information Disclosure
slug: 2026-05-glances-xmlrpc-cors
description: The Glances XML-RPC server exposes sensitive system information due to a permissive CORS policy and missing Content-Type validation, enabling attackers to bypass CORS restrictions and steal data like hostnames, OS details, IP addresses, and process lists.
date: "2026-03-30T17:01:44Z"
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

The Glances system monitoring tool, when run in server mode using the XML-RPC interface (initiated with `glances -s` or `glances --server`), is vulnerable to a cross-origin information disclosure. This vulnerability exists because the XML-RPC server sends the `Access-Control-Allow-Origin: *` header on every HTTP response without validating the `Content-Type` header. An attacker can exploit this by crafting a CORS "simple request" (a POST request with `Content-Type: text/plain`) containing a…
