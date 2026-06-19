---
title: undici WebSocket Client Vulnerable to Denial of Service (CVE-2026-12151)
slug: 2026-06-undici-websocket-dos
description: The `undici` WebSocket client is vulnerable to CVE-2026-12151, a high-severity denial of service attack where a malicious WebSocket server can stream numerous small continuation frames that bypass `maxPayloadSize` checks, causing unbounded memory growth and exhaustion in affected client processes.
date: "2026-06-19T14:26:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - javascript
  - npm
  - nodejs
products:
  - undici (versions prior to 6.27.0)
  - undici (versions 7.0.0 through 7.27.x)
  - undici (versions 8.0.0 through 8.4.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Resource Exhaustion
references:
  - https://github.com/advisories/GHSA-vxpw-j846-p89q
rules:
  - title: Detects CVE-2026-12151 Exploitation — Node.js Application Error (Windows)
    description: Detects CVE-2026-12151 exploitation — Node.js process crash due to application error on Windows, potentially indicating an out-of-memory condition caused by the undici WebSocket client vulnerability.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - application_log
      - windows
  - title: Detects CVE-2026-12151 Exploitation — Node.js Process OOM/Crash (Linux Syslog)
    description: Detects CVE-2026-12151 exploitation — Linux syslog entries indicating a Node.js process (node) was killed due to out-of-memory (OOM) conditions or crashed, potentially caused by the undici WebSocket client vulnerability.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - syslog
      - linux
rules_count: 2
---

The `undici` WebSocket client, used in various Node.js applications, has been identified with a high-severity denial of service vulnerability, CVE-2026-12151, which affects all versions prior to `6.27.0`, `7.0.0` through `7.27.x`, and `8.0.0` through `8.4.x`. This flaw, published on June 19, 2026, allows a malicious WebSocket server to exploit an improper validation logic where the `maxPayloadSize` is enforced on the cumulative byte count of fragments but not on the total number of fragments. Attackers can stream many small or empty continuation frames that individually pass size checks but collectively lead to uncontrolled memory allocation within the client. This results in memory exhaustion and a denial of service for any `undici`-dependent application acting as a WebSocket client and connecting to an attacker-controlled endpoint. Defenders should prioritize patching to prevent application instability and crashes.

## Attack Chain

1.  An attacker operates a specially crafted, malicious WebSocket server designed to exploit `CVE-2026-12151`.
2.  A vulnerable `undici` WebSocket client, integrated into a target application, is induced to establish a connection to the attacker's server (e.g., through a malicious link, compromised third-party service, or supply chain injection).
3.  Upon successful connection, the malicious server sends an initial, valid WebSocket message fragment to maintain an active session.
4.  The server then begins to continuously stream a large quantity of very small or entirely empty WebSocket continuation frames to the connected `undici` client.
5.  The `undici` client's internal `maxPayloadSize` validation logic, which checks the cumulative byte count, passes for each individual small or empty frame.
6.  Despite passing individual frame size checks, the client's memory buffer, responsible for reassembling the fragmented message, grows without bound due to the lack of a limit on the number of fragments.
7.  The vulnerable `undici` client process rapidly consumes available system memory, leading to an out-of-memory (OOM) condition on the host system.
8.  The operating system (Windows, Linux, or macOS) terminates the `undici` client process or the entire application due to memory exhaustion, resulting in a denial of service.

## Impact

The successful exploitation of CVE-2026-12151 leads directly to a denial of service for applications utilizing the vulnerable `undici` WebSocket client. Affected systems will experience rapid, unbounded memory growth, culminating in the termination of the client process or the entire application by the operating system due to out-of-memory conditions. This can cause significant operational disruption, service unavailability, and potential data loss for critical services that rely on `undici` for WebSocket communication. While specific victim counts are not available, any Node.js application using `undici` for WebSocket client functionality, especially those connecting to external or untrusted endpoints, is susceptible to this severe impact.

## Recommendation

*   Upgrade the `undici` package in all affected Node.js applications immediately to a patched version (v6.27.0, v7.28.0, or v8.5.0) as referenced in the GHSA advisory.
*   Deploy the Sigma rules in this brief to your SIEM/EDR to detect Node.js application crashes or abnormal terminations that could indicate successful exploitation of CVE-2026-12151.
*   Enable application-level logging for Node.js processes, specifically capturing errors related to memory allocation failures or unexpected process exits, to activate the rules above.
*   Review network egress policies for applications using the `undici` WebSocket client to ensure they only connect to trusted and necessary WebSocket endpoints, reducing exposure to malicious servers.
