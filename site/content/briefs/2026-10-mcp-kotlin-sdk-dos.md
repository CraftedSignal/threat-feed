---
title: Denial of Service via Uncontrolled Memory Allocation in MCP Kotlin SDK
slug: 2026-10-mcp-kotlin-sdk-dos
description: The MCP Kotlin SDK through version 0.15.0 is vulnerable to denial of service due to the absence of a maxFrameSize limit in the Ktor WebSocket configuration, allowing remote clients to trigger heap exhaustion.
date: "2026-10-11T14:01:13Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:model_context_protocol:mcp_kotlin_sdk:*:*:*:*:*:*:*:*
vendors:
  - Model Context Protocol
products:
  - MCP Kotlin SDK (<= 0.15.0)
cves:
  - id: CVE-2026-108714
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108714
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications currently using MCP Kotlin SDK versions 0.15.0 or lower
      owner: Application Security
      due: 24h
      evidence: CVE-2026-108714
  mitigation_plan:
    - priority: immediate
      action: Upgrade MCP Kotlin SDK to version >0.15.0 once available from vendor
      owner: IT Operations
      addresses: CVE-2026-108714
      evidence: NVD vulnerability detail
---

The MCP Kotlin SDK, specifically versions up to and including 0.15.0, contains an uncontrolled memory allocation vulnerability (CVE-2026-108714) within the `Application.mcpWebSocket` component. The vulnerability arises because the SDK initializes Ktor WebSockets without explicitly configuring a `maxFrameSize` limit. This oversight allows a remote attacker to send crafted WebSocket frame headers that declare very large payload sizes, approaching 2 GiB. By initiating one or a small number of concurrent connections and sending these malformed headers, an attacker can force the server to attempt massive heap allocations, leading to rapid memory exhaustion and a subsequent denial of service (DoS) state. This vulnerability impacts any service utilizing the affected SDK version for WebSocket communication, as the resource consumption occurs before the application logic processes the data.

## Impact

Successful exploitation results in an immediate denial of service for the target application. By consuming available heap memory, the attack forces the JVM to trigger excessive garbage collection cycles or causes an `OutOfMemoryError`, rendering the service unresponsive to legitimate users. Given the nature of WebSocket services, this disruption affects real-time communication channels and connected clients, potentially impacting broader infrastructure depending on the application's role.

## Recommendation

1. Patch immediately by upgrading to a version of the MCP Kotlin SDK that enforces a mandatory `maxFrameSize` limit in the `Application.mcpWebSocket` configuration.
2. Implement global memory monitoring and alerting for JVM heap usage to detect rapid, anomalous memory spikes that precede a crash.
3. Review existing Ktor WebSocket configurations in all applications using the MCP Kotlin SDK to ensure `maxFrameSize` and `maxFrameSize` are explicitly constrained to reasonable bounds appropriate for the application traffic.
