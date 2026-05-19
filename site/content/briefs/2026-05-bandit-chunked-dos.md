---
title: Bandit HTTP/1 Chunked Request DoS Vulnerability
slug: 2026-05-bandit-chunked-dos
description: 'Bandit''s HTTP/1 chunked-body reader silently drops the request size cap, leading to excessive memory buffering. An unauthenticated attacker can crash Bandit-fronted Phoenix/Plug applications by sending a single ''Transfer-Encoding: chunked'' request to any URL, causing BEAM memory exhaustion and a denial-of-service.'
date: "2026-05-19T19:25:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - vulnerability
  - bandit
vendors:
  - Erlang
products:
  - bandit (>= 1.4.0, < 1.11.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-39803
    epss: 0.00365
references:
  - https://github.com/advisories/GHSA-9q9q-324x-93r2
  - CVE-2026-39803
rules:
  - title: Detect Bandit Chunked Request DoS Attempt
    description: 'Detects CVE-2026-39803 exploitation — HTTP POST requests with ''Transfer-Encoding: chunked'' and large request sizes, potentially indicating a denial-of-service attempt against Bandit servers.'
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
rules_count: 1
---

A denial-of-service vulnerability exists in the Bandit HTTP/1 chunked-body reader. This vulnerability, discovered in May 2026, stems from the reader not respecting the configured request size cap (e.g., Plug.Parsers' default 8 MB length). An attacker can exploit this vulnerability by sending a single, unauthenticated `Transfer-Encoding: chunked` request to any URL of a Bandit-fronted Phoenix/Plug application. Due to the lack of size limiting in `lib/bandit/http1/socket.ex`, the entire request body is buffered in memory, leading to BEAM out-of-memory (OOM) errors, effectively crashing the server. This issue impacts Bandit versions 1.4.0 through 1.11.0 and poses a significant risk to Phoenix applications using Bandit as their web server.

## Attack Chain

1.  The attacker sends an HTTP POST request to any endpoint on a Bandit-fronted Phoenix application.
2.  The request includes the header `Transfer-Encoding: chunked` to trigger the vulnerable chunked-body reader in Bandit.
3.  The request also sets `Content-Type` to a type handled by `Plug.Parsers` (e.g., `application/json`).
4.  Bandit's `read_data/2` function in `lib/bandit/http1/socket.ex` is invoked to handle the chunked request body.
5.  The `read_data/2` function calls `do_read_chunked_data!/5`, but omits the configured `:length` cap.
6.  The `do_read_chunked_data!/5` function recursively accumulates all chunks into an iolist.
7.  `IO.iodata_to_binary/1` then materializes the entire iolist as a single binary in memory.
8.  The BEAM process exhausts its memory, leading to an out-of-memory error and crashing the server, resulting in a denial of service.

## Impact

This vulnerability enables an unauthenticated pre-route denial-of-service attack via BEAM memory exhaustion. A single request from a single connection is sufficient to crash the server. This affects nearly every Phoenix application using Bandit, as `Plug.Parsers` is typically mounted ahead of routing and authentication, and the configured `length:` caps are ineffective on the chunked path. This can lead to significant service disruptions and downtime.

## Recommendation

*   Deploy the Sigma rule `Detect Bandit Chunked Request DoS Attempt` to your SIEM to detect suspicious chunked requests.
*   Upgrade to Bandit version 1.11.1 or later to patch CVE-2026-39803.
*   Monitor network traffic for abnormally large chunked requests originating from single source IPs.
*   Review and adjust memory limits on your BEAM processes to mitigate the impact of potential memory exhaustion attacks.
