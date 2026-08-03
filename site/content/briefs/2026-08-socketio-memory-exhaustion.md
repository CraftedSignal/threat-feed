---
title: Memory Exhaustion in Socket.IO Parser
slug: 2026-08-socketio-memory-exhaustion
description: A memory exhaustion vulnerability in socket.io-parser (CVE-2026-69185) allows remote attackers to trigger denial-of-service by sending specially crafted packets containing a large number of binary attachments.
date: "2026-08-03T20:48:28Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - javascript
  - npm
  - supply-chain
vendors:
  - Socket.IO
products:
  - socket.io-parser (4.x)
  - socket.io-parser (3.x)
  - socket.io-parser (2.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A specially crafted Socket.IO packet can make the server wait for a large number of binary attachments and buffer them, which can be exploited to make the server run out of memory.
    confidence_band: high
cves:
  - id: CVE-2026-69185
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-2m8v-j782-fhvr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69185
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Audit dependency trees for vulnerable socket.io-parser versions.
      owner: Application Security
      due: 48h
      evidence: Source explicitly lists affected versions.
  mitigation_plan:
    - priority: immediate
      action: Upgrade socket.io-parser to fixed versions.
      owner: IT Operations
      addresses: CVE-2026-69185
      evidence: Source provides specific fixed version ranges.
---

Socket.IO, a widely used library for real-time bidirectional communication, contains a memory exhaustion vulnerability within its parser component, identified as CVE-2026-69185. The vulnerability resides in how the `socket.io-parser` handles binary attachments. An attacker can transmit a specially crafted, malicious packet that claims to contain a large number of attachments or forces the parser to allocate memory for those attachments in a way that exceeds server capacity. 

Because the server attempts to buffer these attachments upon receiving the packet, it can lead to rapid memory consumption, effectively resulting in a denial-of-service (DoS) condition. This issue affects various versions of the `socket.io-parser` dependency used across the 4.x, 2.x, and legacy client versions of Socket.IO. Since the parser is a fundamental component of the library's messaging architecture, any application exposing a WebSocket interface that parses these packets is inherently vulnerable. There are no configuration-based workarounds; organizations must update the library to the specific patched versions provided by the vendor.

## Impact

The impact of this vulnerability is a high-severity denial-of-service. If exploited, an attacker can crash individual server instances or exhaust system resources, leading to service disruption for real-time applications. Given the ubiquitous nature of Socket.IO in web and mobile backends, this affects any sector utilizing real-time communication, including messaging platforms, collaborative tools, and financial market data feeds. 

## Recommendation

* Identify all applications in the environment using `socket.io` or `socket.io-client` by scanning `package-lock.json` or `yarn.lock` files for the vulnerable `socket.io-parser` versions identified in the Affected Products list.
* Update all instances of `socket.io-parser` to version 4.2.7 or 3.4.5, or the relevant fixed version for older client libraries.
* Monitor server memory utilization metrics (e.g., resident set size, heap usage) in orchestration platforms like Kubernetes or cloud-based server environments to detect sudden, unexplained memory spikes consistent with DoS attempts.
* Implement request size limits and connection timeouts at the Load Balancer or Reverse Proxy layer to mitigate the impact of abnormally large or resource-intensive incoming packets.
