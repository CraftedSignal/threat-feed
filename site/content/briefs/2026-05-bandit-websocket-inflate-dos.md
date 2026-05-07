---
title: Bandit WebSocket permessage-deflate unbounded inflate leads to DoS
slug: 2026-05-bandit-websocket-inflate-dos
description: Bandit versions 0.5.8 before 1.11.0 are vulnerable to denial of service when permessage-deflate is enabled, allowing an unauthenticated client to exhaust the BEAM's memory with a single, small, compressed WebSocket frame due to unbounded decompression.
date: "2026-05-07T03:36:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - websocket
  - denial-of-service
  - erlang
vendors:
  - Erlang
products:
  - bandit (>= 0.5.8, < 1.11.0)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588.002
    technique_name: 'Obtain Capabilities: Tool'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: 'Endpoint Denial of Service: Resource Exhaustion'
references:
  - https://github.com/advisories/GHSA-frh3-6pv6-rc8j
rules:
  - title: Detect WebSocket Handshake with permessage-deflate
    description: Detects WebSocket handshake requests that include the 'permessage-deflate' extension, indicating a potentially vulnerable configuration if compression is enabled.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect High BEAM Memory Usage
    description: Detects unusually high BEAM memory usage, potentially indicating a memory exhaustion attack related to the permessage-deflate vulnerability in Bandit.
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1588
    data_sources:
      - process_creation
      - linux
  - title: Detect Bandit permessage-deflate option enabled
    description: 'Detects when the Bandit option permessage-deflate is enabled by looking for compress: true in the websocket options.'
    platform: sigma
    severity: informational
    tactics:
      - configuration
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

Bandit, a web server for the Erlang ecosystem, is vulnerable to a denial-of-service (DoS) attack. The vulnerability exists in versions 0.5.8 before 1.11.0 when the `permessage-deflate` WebSocket extension is enabled. An unauthenticated client can send a small, specially crafted compressed WebSocket frame that, when decompressed, expands to a significantly larger size, exhausting the server's memory. This occurs because the inflate step within Bandit lacks an output-size cap. This vulnerability affects applications that have explicitly enabled `compress: true` when upgrading a connection to a WebSocket, as stock Phoenix and LiveView apps default to `compress: false`. The attack occurs before any application-level code execution, making it difficult to mitigate without patching the Bandit library itself.

## Attack Chain

1. An unauthenticated client establishes a TCP connection to the Bandit server.
2. The client sends a WebSocket handshake request with `Sec-WebSocket-Extensions: permessage-deflate`.
3. The Bandit server negotiates the `permessage-deflate` extension if both `websocket_options.compress` and `connection_opts.compress` are true.
4. The client sends a WebSocket text frame with the RSV1 bit set to 1, indicating compressed data. The compressed frame is crafted to have a high compression ratio (e.g., 1024:1).
5. The Bandit server receives the compressed frame and begins decompression using `:zlib.inflate/2` in `lib/bandit/websocket/permessage_deflate.ex`.
6. The inflation process lacks any output-size limit, allowing the decompressed data to grow unbounded in memory.
7. `IO.iodata_to_binary/1` materializes the entire decompressed payload into a single binary in the connection process's heap.
8. The server exhausts its available memory, leading to a denial-of-service condition as the BEAM process is OOM-killed or becomes unresponsive.

## Impact

Successful exploitation results in a denial-of-service condition, potentially crashing the BEAM and rendering the Bandit-fronted application unavailable. A single, small compressed frame (~6MiB in the provided PoC) is sufficient to trigger the vulnerability, and concurrent connections will amplify the impact linearly. Applications that have enabled permessage-deflate for bandwidth savings are particularly at risk, as they may not be aware of the inherent unbounded-inflate DoS. This can affect any service using Bandit webserver which explicitly enables the `compress` option, leading to potential service outages.

## Recommendation

*   Disable the `compress: true` option when calling `WebSockAdapter.upgrade/4` as a temporary workaround to mitigate the vulnerability.
*   Monitor process memory usage on systems running Bandit web servers, looking for sudden and significant increases, particularly after WebSocket connections are established. Consider creating a Sigma rule for this behavior based on process memory metrics.
*   Upgrade to Bandit version 1.11.0 or later once available to address the vulnerability with the fix suggested: "thread a maximum-output-size through to inflate and either error out or return resumable chunks once exceeded, mirroring how the HTTP content-length path bounds reads via `:length`.".
*   Deploy the Sigma rule detecting WebSocket handshake with `permessage-deflate` to identify potentially vulnerable configurations.
