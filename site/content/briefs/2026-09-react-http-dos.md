---
title: Denial of Service via Malformed HTTP Chunked Encoding in react/http
slug: 2026-09-react-http-dos
description: A malformed HTTP chunked body triggers an infinite loop in the react/http ChunkedDecoder, causing 100% CPU usage and service disruption in both server and client implementations.
date: "2026-09-18T01:11:26Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:reactphp:http:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - php
  - vulnerability
vendors:
  - ReactPHP
products:
  - react/http (>= 0.6.0, <= 1.11.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'A malformed HTTP message using Transfer-Encoding: chunked can drive React\Http\Io\ChunkedDecoder into an infinite loop, pegging a CPU core and freezing the event loop.'
    confidence_band: high
cves:
  - id: CVE-2026-84997
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-x424-64qh-5j54
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84997
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade react/http to a version newer than 1.11.0
      owner: Development
      due: 48h
      evidence: Source explicitly identifies version range >= 0.6.0, <= 1.11.0 as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Deploy or tune reverse proxy to normalize HTTP chunked encoding before reaching ReactPHP components.
      owner: IT Operations
      addresses: CVE-2026-84997
      evidence: Source states reverse proxies that normalize HTTP requests mitigate the server-side vector.
---

The ReactPHP `react/http` package (versions 0.6.0 through 1.11.0) contains a vulnerability in the `ChunkedDecoder::handleData()` method. The decoder enters an infinite loop when processing specific malformed HTTP chunked bodies, leading to a denial-of-service condition. Because ReactPHP utilizes a single-threaded event loop, this infinite loop pegs a CPU core and halts all other event processing, effectively freezing the application.

The vulnerability manifests in two primary scenarios: 
1. Terminal-chunk trailers where `strpos()` fails to locate a CRLF, causing the buffer to never advance.
2. Off-by-one errors after a completed chunk where two bytes slip past existing guards, causing the loop to re-enter with identical state.

The vulnerability impacts both the `HttpServer` (server-side, exploitable by malicious clients) and the `Browser` component (client-side, exploitable by malicious servers). Servers protected by a reverse proxy that normalizes HTTP traffic may mitigate the server-side vector, but client-side applications fetching attacker-influenced URLs remain fully exposed.

## Attack Chain

1. Attacker identifies a target application utilizing `react/http` (versions >= 0.6.0, <= 1.11.0).
2. For server-side attacks, the attacker crafts a malicious HTTP request with `Transfer-Encoding: chunked`.
3. Attacker includes a terminating `0` chunk followed by trailer data without a trailing `\r\n` sequence.
4. The request is passed to the `HttpServer` component and subsequently the `ChunkedDecoder`.
5. `ChunkedDecoder::handleData()` enters an infinite `while` loop due to the buffer state never advancing.
6. The process hits 100% CPU usage on a single core, stalling the event loop.
7. The application stops responding to all other legitimate client requests.
8. Service availability is lost until the process is manually killed or restarted.

## Impact

Successful exploitation results in a full denial of service for the target application. Since ReactPHP is single-threaded, a single malicious request freezes the entire event loop, preventing the processing of legitimate traffic. This impacts any PHP application relying on these components for HTTP handling, including services acting as clients (Browser) that perform external fetches.

## Recommendation

1. Update `react/http` to a version beyond 1.11.0.
2. If an immediate update is not feasible, implement a reverse proxy (e.g., nginx) in front of `HttpServer` to normalize incoming HTTP traffic and filter non-compliant chunked payloads.
3. Review all client-side logic using `React\Http\Browser` to ensure that responses from external services are validated or that the fetching service is isolated from core application processing.
4. Implement resource monitoring to alert on persistent 100% CPU spikes in PHP-based HTTP services.
