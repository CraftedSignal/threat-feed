---
title: Engine.IO WebTransport Denial of Service
slug: 2026-08-engineio-dos
description: A vulnerability in Engine.IO versions 6.5.0 through 6.6.6 allows unauthenticated attackers to cause a process crash by sending a crafted WebTransport upgrade request.
date: "2026-08-31T23:58:36Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:socket.io:engine.io:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:socket:engine.io:*:*:*:*:*:node.js:*:*
vendors:
  - Socket.IO
products:
  - engine.io (>= 6.5.0 < 6.6.7)
cves:
  - id: CVE-2026-59724
    cvss: 7.5
    epss: 0.00609
references:
  - https://github.com/advisories/GHSA-gr94-w7qr-f4j3
  - https://github.com/socketio/socket.io/commit/1fa1f46cd420ac5b57bb4c04c959b58f3c79158c
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-59724
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade engine.io to 6.6.7
      owner: IT Operations
      due: 24h
      evidence: The issue was fixed in engine.io 6.6.7
    - action: Disable WebTransport if upgrading is not possible
      owner: Application Security
      due: 24h
      evidence: 'Workaround: ensure webtransport is not included in the enabled transports list'
  mitigation_plan:
    - priority: immediate
      action: Remove 'webtransport' from the transports configuration array
      owner: Application Security
      addresses: CVE-2026-59724
      evidence: 'Workaround: use only the default HTTP long-polling and WebSocket transports'
---

The Engine.IO library, a core component for real-time communication in Socket.IO applications, contains a denial of service (DoS) vulnerability (CVE-2026-59724) affecting deployments where WebTransport support is explicitly enabled. The vulnerability stems from improper validation of session ID lookups in the WebTransport upgrade handshake. An unauthenticated remote attacker can submit a crafted upgrade request with a session ID value like "__proto__". Because the server fails to verify that the key is an own property of the clients object, the lookup resolves to an inherited prototype property, triggering a TypeError. This error, occurring in an asynchronous context, leads to an unhandled Promise rejection that terminates the Node.js process. This vulnerability affects Engine.IO versions 6.5.0 up to 6.6.6. Defenders should prioritize upgrading to version 6.6.7 or disabling WebTransport support if the immediate upgrade is not feasible.

## Impact

Successful exploitation results in the immediate termination of the Engine.IO server process. In production environments without robust process supervision, this causes a total loss of service. If a process supervisor is present, repeated exploitation by an attacker will result in continuous crash loops, effectively preventing service availability for legitimate users. This threat specifically targets web applications using the Node.js ecosystem and real-time Socket.IO communication.

## Recommendation

- Upgrade the Engine.IO dependency to version 6.6.7 or later to patch CVE-2026-59724.
- If upgrading is delayed, immediately modify the Engine.IO configuration to remove "webtransport" from the enabled transports list.
- Monitor server logs for repeated process crashes or unusual WebTransport upgrade requests containing prototype manipulation keys.
- Inspect HTTP/3 and WebTransport gateway traffic at the reverse proxy layer for anomalous session ID formatting.
