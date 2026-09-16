---
title: Resource Exhaustion in node-opcua via TCP Socket Leak
slug: 2026-09-node-opcua-socket-leak
description: A vulnerability in node-opcua (CVE-2026-68904) causes TCP socket exhaustion and process crashes when clock skew triggers continuous reconnection cycles.
date: "2026-09-16T19:07:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:node-opcua:node-opcua:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - nodejs
  - opcua
  - resource-exhaustion
vendors:
  - node-opcua
products:
  - node-opcua (>= 2.0.0, < 2.170.0)
  - node-opcua-client (>= 2.0.0, < 2.170.0)
  - node-opcua-transport (>= 2.0.0, < 2.170.0)
affected_os:
  - Linux
cves:
  - id: CVE-2026-68904
    cvss: 7
references:
  - https://github.com/advisories/GHSA-r2pf-9cw4-5j65
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade node-opcua packages to 2.170.0
      owner: Development
      due: 48h
      evidence: Source explicitly names 2.170.0 as the version containing the fix for CVE-2026-68904
  mitigation_plan:
    - priority: immediate
      action: Configure NTP to synchronize OPC UA client and server clocks
      owner: IT Operations
      addresses: CVE-2026-68904
      evidence: Source identifies clock skew as the primary trigger for the reconnection cycle
---

CVE-2026-68904 is a resource exhaustion vulnerability in the node-opcua library affecting versions prior to 2.170.0. The vulnerability arises from an improper reconnection logic when the client environment has a clock skew relative to the connected OPC UA server. When the server returns a BadInvalidTimestamp error due to timestamp validation failure, the node-opcua keepalive manager incorrectly interprets this as a fatal transport-level network outage. This triggers an immediate reconnection attempt every keepAliveInterval (default 3 seconds). 

Simultaneously, the library's transport layer uses socket.end() rather than socket.destroy() during failed handshakes. This sends a TCP FIN but does not forcefully close the connection, resulting in orphaned sockets remaining in a FIN-WAIT-2 state indefinitely. The cumulative effect of rapid, repeated reconnections caused by the misidentified error, combined with the failure to properly clean up sockets, leads to file descriptor exhaustion and memory depletion, eventually resulting in an OOM-kill or process crash.

## Impact

Successful exploitation (via natural clock drift or deliberate manipulation of the server timestamp) leads to a persistent denial-of-service condition for the node-opcua client process. Affected industrial automation systems relying on this library may experience total loss of connectivity to OPC UA servers, process interruptions, and unrecoverable service downtime. The bug has been confirmed in node-opcua versions 2.169.0 and below.

## Recommendation

Prioritized actions for development and security teams:
- Upgrade node-opcua, node-opcua-client, and node-opcua-transport to version 2.170.0 or later to patch the connection handling logic.
- Until patching is possible, implement system-level monitoring for TCP socket counts on hosts running node-opcua services (e.g., ss -antp | grep FIN-WAIT-2).
- Synchronize system clocks between OPC UA clients and servers using NTP or PTP to prevent the BadInvalidTimestamp error condition from triggering the flawed reconnection logic.
