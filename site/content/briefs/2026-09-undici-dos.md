---
title: Undici WebSocket Client Denial of Service via Unsolicited Subprotocol
slug: 2026-09-undici-dos
description: The undici WebSocket client library is vulnerable to a denial-of-service attack (CVE-2026-19534) that crashes the Node.js process when a server returns an unrequested Sec-WebSocket-Protocol header.
date: "2026-09-29T22:18:30Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:nodejs:undici:*:*:*:*:*:node.js:*:*
vendors:
  - OpenJS Foundation
products:
  - undici (>= 6.7.0, < 6.28.1)
  - undici (>= 7.0.0, < 7.29.1)
  - undici (>= 8.0.0, < 8.10.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The throw occurs in a queueMicrotask callback with no surrounding try/catch, so it propagates as an uncaught exception and terminates the Node.js process.
    confidence_band: high
cves:
  - id: CVE-2026-19534
    cvss: 7.5
    epss: 0.00394
references:
  - https://github.com/advisories/GHSA-rfgv-xxqx-mfg5
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade undici to 6.28.1, 7.29.1, or 8.10.2
      owner: IT Operations
      addresses: CVE-2026-19534
      evidence: Patches for CVE-2026-19534 are available in versions 6.28.1, 7.29.1, or 8.10.2.
---

The undici package, a popular HTTP/1.1 and WebSocket client for Node.js, contains a flaw in its WebSocket implementation that results in a process-wide denial of service. When establishing a WebSocket connection, the library fails to properly handle unexpected `Sec-WebSocket-Protocol` headers returned by a server in its `101 Switching Protocols` response. Specifically, if the client did not request a subprotocol but the server includes one, the internal logic throws an uncaught `TypeError` within a `queueMicrotask` callback. 

Because this error occurs outside of a standard `try`/`catch` block, it results in an unhandled exception that causes the entire Node.js runtime to terminate. This vulnerability, tracked as CVE-2026-19534, can be exploited by an attacker operating a malicious WebSocket server or by an adversary performing a machine-in-the-middle attack on unencrypted `ws://` connections. Affected versions include all releases from 6.7.0 through those immediately preceding 6.28.1, 7.29.1, and 8.10.2. Defenders should prioritize patching, as there is no viable workaround for this flaw.

## Impact

The vulnerability allows for remote, unauthenticated denial of service against any application utilizing the undici WebSocket client. Successful exploitation results in immediate application downtime due to process termination. This represents a significant availability risk for services that programmatically connect to external or untrusted third-party WebSocket endpoints.

## Recommendation

- Immediately upgrade vulnerable installations of undici to version 6.28.1, 7.29.1, or 8.10.2 to remediate CVE-2026-19534.
- Audit application codebases to identify instances where the `new WebSocket(url)` constructor is used to connect to third-party or untrusted server endpoints.
- Enforce TLS (wss://) for all WebSocket connections to mitigate the risk of machine-in-the-middle injection of the malicious `Sec-WebSocket-Protocol` header.
