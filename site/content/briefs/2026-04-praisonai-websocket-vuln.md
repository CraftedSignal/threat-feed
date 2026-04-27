---
title: PraisonAI Unauthenticated WebSocket Allows Resource Exhaustion
slug: 2026-04-praisonai-websocket-vuln
description: PraisonAI before version 4.5.128 is vulnerable to resource exhaustion and API credit draining due to the `/media-stream` WebSocket endpoint accepting unauthenticated connections, allowing attackers to exhaust server resources and drain OpenAI API credits.
date: "2026-04-09T22:16:35Z"
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

PraisonAI, a multi-agent teams system, contains a vulnerability in versions prior to 4.5.128 that exposes the `/media-stream` WebSocket endpoint in its call module. This endpoint lacks authentication or Twilio signature validation, allowing any client to establish a connection. Each successful connection initiates an authenticated session to OpenAI's Realtime API, utilizing the server's API key. Due to the absence of rate limits, connection limits, or message size restrictions, a malicious…
