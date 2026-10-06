---
title: Prototype Pollution in @socket.io/cluster-engine
slug: 2026-10-socketio-prototype-pollution
description: The @socket.io/cluster-engine package is vulnerable to prototype pollution when processing attacker-controlled session IDs, allowing an attacker to cause a denial of service via process crash.
date: "2026-10-06T00:45:04Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:socket.io:cluster-engine:0.1.0:*:*:*:*:node.js:*:*
tags:
  - nodejs
  - vulnerability
  - prototype-pollution
  - dos
vendors:
  - Socket.IO
products:
  - cluster-engine (< 0.1.1)
cves:
  - id: CVE-2026-102600
    cvss: 7.5
    epss: 0.00366
references:
  - https://github.com/advisories/GHSA-wfpm-5gcm-94cg
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102600
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade @socket.io/cluster-engine to 0.1.1 or later
      owner: Development
      due: 48h
      evidence: The issue was fixed in @socket.io/cluster-engine@0.1.1
  mitigation_plan:
    - priority: immediate
      action: Implement input sanitization for session IDs to reject prototype-pollution-related keys
      owner: Development
      addresses: CVE-2026-102600
      evidence: Rejecting or sanitizing suspicious session IDs before they reach the cluster engine
---

The @socket.io/cluster-engine package, used for managing socket connections in clustered environments, contains a prototype pollution vulnerability (CVE-2026-102600) in version 0.1.0. The vulnerability exists due to unsafe handling of client-provided session identifiers during the lookup process. An attacker can craft requests using special property names, such as '__proto__' or 'constructor', as session identifiers. Because the engine incorrectly treats these keys as valid session lookups, it attempts to access properties from the object prototype chain rather than the expected client storage objects. This unexpected state leads to internal server errors and, ultimately, a process crash, effectively resulting in a denial-of-service condition for affected Node.js applications. This issue specifically affects deployments utilizing the cluster-engine component.

## Impact

The vulnerability results in a denial of service (DoS) by crashing the Node.js process hosting the @socket.io/cluster-engine. This impact is significant for real-time applications relying on persistent socket connections, as the crash disrupts all connected clients on that process. 

## Recommendation

- Upgrade the @socket.io/cluster-engine package to version 0.1.1 or later to remediate CVE-2026-102600.
- Implement input validation on session identifiers in custom middleware to reject keys containing '__proto__', 'constructor', or 'prototype' before passing them to the cluster engine as a defense-in-depth measure.
