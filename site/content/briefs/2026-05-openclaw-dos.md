---
title: OpenClaw Denial-of-Service via Oversized WebSocket Frames
slug: 2026-05-openclaw-dos
description: OpenClaw versions prior to 2026.4.10 are vulnerable to a denial-of-service attack where remote attackers can send oversized WebSocket frames to the voice-call realtime path, causing service unavailability.
date: "2026-05-05T12:16:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - websocket
  - cve-2026-42437
vendors:
  - openclaw
products:
  - openclaw < 2026.4.10
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-42437
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42437
  - https://github.com/openclaw/openclaw/commit/afadb7dae6738819ad9c7d2597ace0516957d20e
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-vw3h-q6xq-jjm5
  - https://www.vulncheck.com/advisories/openclaw-denial-of-service-via-oversized-websocket-frames-in-voice-call-realtime-path
rules:
  - title: Detect Large WebSocket Frames
    description: Detects unusually large WebSocket frames, potentially indicating a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - zeek
  - title: Detect Multiple WebSocket Connections from Single IP
    description: Detects a high number of WebSocket connections originating from a single IP address within a short time frame, potentially indicating a DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

OpenClaw versions 2026.4.9 and earlier are vulnerable to a denial-of-service (DoS) attack due to improper validation of WebSocket frame sizes on the voice-call realtime path. This vulnerability, identified as CVE-2026-42437, allows remote attackers to send oversized WebSocket frames, leading to resource exhaustion and service unavailability. Deployments exposing the vulnerable webhook path are at risk. Upgrading to version 2026.4.10 or later resolves this vulnerability. The issue was reported and patched in April 2026.

## Attack Chain

1.  Attacker identifies an OpenClaw deployment exposing the voice-call realtime WebSocket path.
2.  Attacker crafts a WebSocket frame exceeding the expected size limits.
3.  Attacker sends the oversized WebSocket frame to the vulnerable endpoint.
4.  The OpenClaw server receives the oversized frame without proper size validation.
5.  The server attempts to process the oversized frame, consuming excessive resources.
6.  Repeated sending of oversized frames leads to resource exhaustion on the server.
7.  The OpenClaw service becomes unresponsive due to resource starvation.
8.  Legitimate users are unable to access voice-call functionalities, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, rendering the OpenClaw voice-call service unavailable. The impact is service disruption. The number of affected deployments is currently unknown, but all OpenClaw instances running versions prior to 2026.4.10 are susceptible if the vulnerable websocket endpoint is exposed.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.10 or later to remediate CVE-2026-42437.
*   Monitor network traffic for unusually large WebSocket frames destined for the voice-call realtime path using a network intrusion detection system.
*   Implement rate limiting on WebSocket connections to mitigate the impact of potential DoS attacks.
