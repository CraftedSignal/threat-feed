---
title: PraisonAI Unauthenticated WebSocket Allows Resource Exhaustion
slug: 2026-04-praisonai-websocket-vuln
description: PraisonAI before version 4.5.128 is vulnerable to resource exhaustion and API credit draining due to the `/media-stream` WebSocket endpoint accepting unauthenticated connections, allowing attackers to exhaust server resources and drain OpenAI API credits.
date: "2026-04-09T22:16:35Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-40116
  - resource-exhaustion
  - websocket
  - api-abuse
  - cloud
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2026-40116
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40116
rules:
  - title: Detect Suspicious PraisonAI WebSocket Connections
    description: Detects a high number of connections to the /media-stream endpoint, which could indicate exploitation of CVE-2026-40116.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of Messages to PraisonAI WebSocket
    description: Detects a high volume of messages to the /media-stream endpoint, indicating potential abuse.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, contains a vulnerability in versions prior to 4.5.128 that exposes the `/media-stream` WebSocket endpoint in its call module. This endpoint lacks authentication or Twilio signature validation, allowing any client to establish a connection. Each successful connection initiates an authenticated session to OpenAI's Realtime API, utilizing the server's API key. Due to the absence of rate limits, connection limits, or message size restrictions, a malicious actor can exploit this vulnerability by creating numerous concurrent connections. This can lead to the exhaustion of server resources and a significant drain on the victim's OpenAI API credits. This vulnerability is addressed and patched in version 4.5.128.

## Attack Chain

1.  Attacker identifies a PraisonAI instance running a vulnerable version (prior to 4.5.128).
2.  Attacker establishes a WebSocket connection to the `/media-stream` endpoint of the PraisonAI instance without providing any authentication credentials.
3.  The PraisonAI server, upon receiving the unauthenticated WebSocket connection, creates an authenticated session with the OpenAI Realtime API using its own API key.
4.  Attacker sends a large volume of messages through the WebSocket connection, exploiting the lack of message rate limits.
5.  Attacker initiates multiple concurrent WebSocket connections to the `/media-stream` endpoint.
6.  The PraisonAI server becomes overloaded due to the excessive number of connections and message processing demands.
7.  The victim's OpenAI API credits are rapidly depleted as the PraisonAI server processes requests from the attacker's connections.
8.  The PraisonAI server experiences degraded performance or becomes completely unresponsive, impacting legitimate users.

## Impact

Successful exploitation of this vulnerability results in resource exhaustion on the PraisonAI server, potentially causing denial of service for legitimate users. Furthermore, it leads to the unauthorized consumption of the victim's OpenAI API credits, resulting in unexpected charges and potential disruption of services reliant on the OpenAI API. The number of affected organizations depends on the prevalence of vulnerable PraisonAI instances deployed.

## Recommendation

*   Upgrade PraisonAI installations to version 4.5.128 or later to patch CVE-2026-40116.
*   Implement rate limiting on WebSocket connections to the `/media-stream` endpoint to mitigate resource exhaustion.
*   Monitor OpenAI API usage for unexpected spikes in activity that may indicate exploitation of this vulnerability.
*   Deploy the Sigma rule `DetectSuspiciousPraisonAIWebSocketConnections` to identify potential exploitation attempts by detecting a high number of connections to the `/media-stream` endpoint.
