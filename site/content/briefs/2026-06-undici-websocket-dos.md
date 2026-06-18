---
title: undici WebSocket Client Vulnerable to Denial of Service via Cumulative Fragment Bypass (CVE-2026-9675)
slug: 2026-06-undici-websocket-dos
description: The undici WebSocket client versions 8.0.0 through 8.4.x are vulnerable to a denial-of-service attack (CVE-2026-9675) where a malicious WebSocket server can cause unbounded memory growth in the client process by sending fragmented uncompressed messages that bypass per-frame size checks but exceed cumulative limits, leading to memory exhaustion and application crashes.
date: "2026-06-18T14:53:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - websocket
  - npm
  - undici
  - client-side
vendors:
  - Node.js Foundation
products:
  - undici (8.0.0)
  - undici (8.1.0)
  - undici (8.2.0)
  - undici (8.3.0)
  - undici (8.4.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-38rv-x7px-6hhq
rules:
  - title: Detects CVE-2026-9675 Exploitation — Node.js Process with Excessive Memory Usage
    description: Detects node.js processes (node.exe on Windows, node on Linux) exhibiting unusually high memory consumption, which could be indicative of a denial-of-service attack leveraging CVE-2026-9675 in the undici WebSocket client.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-9675 Exploitation — Node.js Process Crash Event
    description: Detects sudden termination or crashes of node.js processes (node.exe on Windows, node on Linux) that might be caused by memory exhaustion from CVE-2026-9675 exploitation in the undici WebSocket client. This rule looks for Windows Event Log entries indicating application crashes.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `undici` WebSocket client, widely used within Node.js applications, has been identified with a critical denial-of-service vulnerability, tracked as CVE-2026-9675. Affecting versions 8.0.0 through 8.4.x, this flaw stems from an insufficient check on the cumulative size of fragmented uncompressed WebSocket messages. While the client correctly enforces `maxPayloadSize` for individual frames, it fails to account for the total size when reassembling multiple small fragments. A malicious or compromised WebSocket server can exploit this by streaming numerous small fragments, each adhering to the per-frame size limit, but collectively leading to an excessively large message. This causes the client process to consume an unbounded amount of memory, resulting in memory exhaustion, application crashes, and ultimately, a denial of service for any application using the vulnerable `undici` WebSocket client. Patches are available in version 8.5.0 and later.

## Attack Chain

1.  An application utilizing the vulnerable `undici` WebSocket client (versions 8.0.0 to 8.4.x) establishes a connection to a remote WebSocket endpoint.
2.  The remote WebSocket endpoint is controlled by an attacker or has been compromised.
3.  The attacker-controlled server initiates the transmission of a fragmented WebSocket message to the `undici` client.
4.  The server carefully crafts and sends multiple small WebSocket fragments, ensuring that the size of each individual fragment remains below the client's `maxPayloadSize` threshold.
5.  The vulnerable `undici` client receives and buffers these fragments, passing the per-frame size validation check.
6.  Due to the vulnerability, the `undici` client does not cumulatively check the total size of the reassembled message, leading to an unbounded buffer growth.
7.  The continuous influx of small fragments causes the `node.exe` process (hosting the `undici` client) to consume an ever-increasing amount of memory.
8.  Eventually, the `node.exe` process exhausts available system memory, leading to its termination, a core dump, or a complete system slowdown, resulting in a denial of service for the affected application.

## Impact

The primary impact of CVE-2026-9675 is a denial of service for applications employing the vulnerable `undici` WebSocket client. When exploited, the targeted client process will experience unbounded memory growth, leading to memory exhaustion. This can manifest as the affected `node.js` application crashing, becoming unresponsive, or being forcibly terminated by the operating system due to resource limits. Such incidents disrupt critical services and can lead to significant downtime, loss of business continuity, and potentially data loss if transactions are not properly handled during the crash. No specific victim counts or targeted sectors were detailed in the advisory, but any application dependent on `undici` for WebSocket communication is at risk.

## Recommendation

*   **Upgrade undici**: Immediately upgrade all deployments of the `undici` package to version 8.5.0 or newer to mitigate CVE-2026-9675. This is the only available workaround.
*   **Deploy Sigma rule "Detect Node.js Process with Excessive Memory Usage"**: Implement the provided Sigma rule to detect `node.exe` or `node` processes exhibiting abnormally high memory consumption, which may indicate an ongoing denial-of-service attack or memory leak.
*   **Deploy Sigma rule "Detect Node.js Process Crash Event"**: Implement the provided Sigma rule to identify sudden termination events for `node.exe` processes, which could be a direct result of memory exhaustion triggered by CVE-2026-9675.
