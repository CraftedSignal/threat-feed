---
title: Engine.IO Polling Transport Connection Exhaustion Vulnerability (CVE-2026-59725)
slug: 2026-07-engineio-dos
description: 'An unauthenticated remote attacker can cause a denial of service in `engine.io` by sending invalid binary POST requests with `Content-Type: application/octet-stream` to Engine.IO protocol v4 polling transports, leading to exhaustion of server-side resources such as HTTP connections, sockets, and file descriptors due to improper connection closure.'
date: "2026-07-20T21:53:08Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:socket:engine.io:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - vulnerability
  - web-application
vendors:
  - Socket.IO
products:
  - engine.io (>= 4.1.0, < 6.6.7)
  - Socket.IO
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker can cause a denial of service...exhaust available HTTP connections, sockets, file descriptors, or related server resources, potentially preventing legitimate clients from connecting.
    confidence_band: high
cves:
  - id: CVE-2026-59725
    cvss: 7.5
    epss: 0.00354
references:
  - https://github.com/advisories/GHSA-r635-g3xr-vw7x
  - https://github.com/socketio/socket.io/commit/fc11285e14964c2132d122164bf130c355f60671
  - https://github.com/socketio/socket.io/blob/main/packages/engine.io/CHANGELOG.md#667-2026-04-27
  - https://github.com/socketio/socket.io
  - https://www.npmjs.com/package/engine.io
rules:
  - title: Detects CVE-2026-59725 Exploitation - Engine.IO DoS Attempt
    description: 'Detects CVE-2026-59725 exploitation - HTTP POST requests targeting Engine.IO polling endpoints with Content-Type: application/octet-stream, which can lead to a Denial of Service.'
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 1
---

A critical denial-of-service vulnerability, identified as CVE-2026-59725, affects `engine.io` versions 4.1.0 through 6.6.6. `engine.io` is a core dependency of the widely used Socket.IO framework. This flaw enables an unauthenticated remote attacker to trigger resource exhaustion on a vulnerable server by sending specially crafted binary `POST` requests. Specifically, by targeting an Engine.IO protocol v4 polling transport with `Content-Type: application/octet-stream` and an invalid request body, the server reports a transport error but crucially fails to properly close the associated HTTP response. This leaves the underlying HTTP connection open, consuming a server-side socket or file descriptor. Repeated execution of this technique can exhaust the server's available HTTP connections, sockets, and other resources, ultimately preventing legitimate clients from connecting and resulting in a denial of service.

## Attack Chain

1. An unauthenticated remote attacker identifies a public-facing web application that utilizes `engine.io` for its Engine.IO protocol v4 polling transports.
2. The attacker crafts an HTTP `POST` request specifically designed to interact with the Engine.IO polling endpoint (e.g., `/engine.io/?EIO=4&transport=polling`).
3. The `Content-Type` header of this `POST` request is set to `application/octet-stream`, and the request body contains malformed or invalid binary data.
4. The attacker sends this malformed `POST` request to the vulnerable `engine.io` server instance.
5. Upon receiving the request, the `engine.io` server processes the malformed binary data, resulting in a transport error.
6. Despite the error, the vulnerable server fails to properly close the HTTP response and the underlying HTTP connection associated with the request.
7. This unclosed connection consumes one of the server's limited resources, such as an HTTP connection, socket, or file descriptor.
8. The attacker repeats steps 2-7 multiple times, progressively exhausting the server's resources and ultimately leading to a Denial of Service condition that prevents legitimate users from connecting.

## Impact

Successful exploitation of CVE-2026-59725 results in a Denial of Service (DoS) for the affected `engine.io` or Socket.IO application. Attackers can exhaust critical server resources, including HTTP connections, network sockets, and file descriptors. This resource depletion prevents legitimate users and clients from establishing new connections or interacting with the application, rendering the service unavailable. The impact can extend to any web application or service that relies on vulnerable `engine.io` versions, potentially affecting a broad range of sectors using Node.js-based web communication frameworks.

## Recommendation

* Upgrade all instances of `engine.io` to version `6.6.7` or later immediately to patch CVE-2026-59725.
* Deploy the `Detects CVE-2026-59725 Exploitation - Engine.IO DoS Attempt` Sigma rule to your SIEM to detect attempts to exploit this vulnerability.
* Configure reverse proxies, load balancers, or Web Application Firewalls (WAFs) to block or reject `POST` requests with `Content-Type: application/octet-stream` targeting Engine.IO protocol v4 endpoints, as described in the `workarounds` section.
* Implement per-IP rate limits and connection limits for Engine.IO endpoints at the network edge to mitigate the impact of repeated requests.
* Enforce strict request and connection timeouts at your HTTP server, reverse proxy, or load balancer to ensure idle or problematic connections are terminated promptly.
