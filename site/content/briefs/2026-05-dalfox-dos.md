---
title: Dalfox Unauthenticated Remote DoS via Closed-Channel Write in ParameterAnalysis
slug: 2026-05-dalfox-dos
description: Dalfox is vulnerable to an unauthenticated remote denial-of-service (DoS) vulnerability (CVE-2026-45090) due to a closed channel write in the `ParameterAnalysis` function, triggered by a crafted POST request that crashes the Dalfox server process.
date: "2026-05-12T15:10:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - vulnerability
  - dalfox
vendors:
  - github.com
products:
  - dalfox
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-2g4x-fq3j-cgq4
  - CVE-2026-45090
rules:
  - title: Detect Dalfox DoS Attack via /scan Endpoint
    description: Detects a Dalfox DoS attack (CVE-2026-45090) via a POST request to the /scan endpoint with a specific payload.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - webserver
  - title: Detect Dalfox API request
    description: Detects API requests to Dalfox server
    platform: sigma
    severity: low
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 2
---

Dalfox, a security tool, is susceptible to an unauthenticated remote denial-of-service vulnerability (CVE-2026-45090) within its `ParameterAnalysis` function. This vulnerability arises from a two-stage worker design where the second stage inadvertently utilizes a closed channel from the first stage. When a scanned parameter is reflected during the second stage of the analysis and `processParams` attempts to write to this already-closed channel, it triggers a Go runtime panic, resulting in the termination of the entire Dalfox process in server mode. This can be exploited remotely by any unauthenticated caller with network access to the Dalfox REST API, as the default configuration lacks an API key and the second stage activates whenever `options.Data != ""` (i.e., the attacker supplies the `data` field) and the target reflects at least one parameter. This issue affects Dalfox versions 2.12.0 and earlier.

## Attack Chain

1. An attacker sends a POST request to the `/scan` endpoint of the Dalfox REST API server.
2. The attacker includes a `url` parameter pointing to a controlled, reflective HTTP server (e.g., `http://127.0.0.1:18083/?q=test`).
3. The attacker includes a JSON payload containing `options` with `"data": "q=test"`, `"mining-dict": true`, and `"use-headless": false`.
4. The `options.Data` value triggers the activation of the second worker stage in `ParameterAnalysis`.
5. The `mining-dict: true` setting populates the POST-body parameter map (`dp`) with numerous entries from the GF-XSS wordlist.
6. The target server reflects the `q` parameter, causing the `vrs` variable to evaluate to true within the `processParams` function.
7. `processParams` attempts to send a `paramResult` to the closed `results` channel: `results <- paramResult`.
8. This operation triggers a Go runtime panic because the `results` channel was already closed after the first stage of `ParameterAnalysis`, causing the Dalfox server process to crash.

## Impact

A successful exploit results in a complete crash of the Dalfox server process upon receiving a single unauthenticated POST request. This leads to the loss of any in-flight scan results, and requires a manual restart of the server. If Dalfox is managed by an automated process manager (such as systemd or Docker with `--restart=always`), this vulnerability can lead to a denial-of-service loop, as the server will repeatedly crash and restart upon receiving malicious requests. The attack requires network access to port 6664 (the default Dalfox API port) and a reflective HTTP server accessible to the Dalfox instance.

## Recommendation

*   Apply the suggested fix (Option 1) by allocating a fresh `results` channel for the second stage within the `ParameterAnalysis` function to prevent writing to a closed channel.
*   As a temporary measure, implement Option 3 and add a `recover` statement in the `processParams` goroutines to catch the panic and prevent the process from crashing while a proper fix is deployed.
*   Deploy the Sigma rule "Detect Dalfox DoS Attack via /scan Endpoint" to detect POST requests to the `/scan` endpoint with the specific `options` payload that triggers the vulnerability.
*   Monitor Dalfox server logs for "panic: send on closed channel" messages originating from `pkg/scanning/parameterAnalysis.go:299`, which indicates a successful exploit of CVE-2026-45090.
