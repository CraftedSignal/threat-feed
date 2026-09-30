---
title: Engine.IO Protocol Revision Mismatch Denial of Service
slug: 2026-09-socket-io-dos
description: A denial-of-service vulnerability in Engine.IO versions 6.6.0 through 6.6.9 allows remote attackers to crash Node.js processes by sending crafted WebSocket upgrade requests with mismatched protocol parameters.
date: "2026-09-30T04:19:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:socket.io:engine.io:*:*:*:*:*:node.js:*:*
vendors:
  - Socket.IO
products:
  - engine.io (>= 6.6.0, < 6.6.10)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A malicious client could exploit this mismatch by establishing a valid Engine.IO session and then sending an upgrade request with a different, or omitted, EIO query parameter.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2gc4-cqfq-p2gv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102599
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade engine.io to 6.6.10 or later
      owner: IT Operations
      due: 24h
      evidence: The issue was fixed in engine.io 6.6.10
  mitigation_plan:
    - priority: immediate
      action: Disable transport upgrades or restrict to websocket only
      owner: Application Security
      addresses: CVE-2026-102599
      evidence: Workarounds provided to reduce exposure
---

Engine.IO, the underlying engine for Socket.IO, contains a denial-of-service (DoS) vulnerability tracked as CVE-2026-102599. The flaw arises from insufficient validation of the Engine.IO (EIO) protocol revision during transport upgrades. When a client initiates an upgrade - such as moving from HTTP polling to a WebSocket transport - the server fails to verify that the protocol revision of the upgrade request matches the version negotiated during the initial session handshake. 

An attacker can exploit this by establishing a legitimate session and then sending a transport upgrade request with a mismatched or omitted `EIO` query parameter. Because the server inconsistently attaches a new transport with a different parser or heartbeat mechanism based on the malformed request, a subsequent crafted heartbeat packet can trigger an uncaught exception, leading to an immediate crash of the Node.js process. This vulnerability affects Engine.IO versions 6.6.0 through 6.6.9 and is present regardless of whether v3 compatibility is enabled.

## Impact

Successful exploitation results in a complete denial-of-service by crashing the Node.js process hosting the Socket.IO server. This impact is significant for real-time applications, potentially affecting all connected users and requiring manual service restarts. The scope of targeting includes any application relying on the vulnerable versions of Engine.IO exposed to public network traffic.

## Recommendation

1. Upgrade the `engine.io` package to version 6.6.10 or later immediately to resolve the underlying validation logic error associated with CVE-2026-102599.
2. If an immediate upgrade is not feasible, update the Socket.IO server configuration to disable transport upgrades by setting `allowUpgrades: false`.
3. Alternatively, restrict allowed transports to `['websocket']` only to bypass the vulnerable upgrade path.
4. Implement application-layer middleware to reject requests containing a session ID (sid) where the `EIO` parameter is missing or inconsistent with the initial session handshake version.
