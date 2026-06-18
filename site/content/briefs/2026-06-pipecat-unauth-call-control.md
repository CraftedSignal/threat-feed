---
title: Pipecat Telephony Runner Unauthenticated Call-Control Abuse
slug: 2026-06-pipecat-unauth-call-control
description: An unauthenticated remote attacker can leverage a missing authorization vulnerability (CWE-862) in the Pipecat development runner's `/ws` WebSocket endpoint to supply a crafted `callSid` in a handshake message, compelling the server to use its configured Twilio, Telnyx, or Plivo credentials to issue authenticated API requests that terminate active calls, resulting in denial of service and credential abuse.
date: "2026-06-18T15:22:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - api-security
  - websocket
  - telephony
  - cwe-862
  - python
vendors:
  - pipecat
  - Twilio
  - Telnyx
  - Plivo
products:
  - pipecat development runner
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: ""
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-j8cv-x86q-rj85
iocs:
  - type: domain
    value: api.twilio.com
  - type: domain
    value: api.telnyx.com
  - type: domain
    value: api.plivo.com
ioc_counts:
  domain: 3
rules:
  - title: Pipecat Telephony Runner Outbound Call Control Request
    description: Detects outbound network connections from a process associated with the pipecat telephony runner (Python) to Twilio, Telnyx, or Plivo API endpoints with URL patterns indicative of call termination. This could suggest exploitation of the unauthenticated call-control vulnerability.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - impact
    techniques:
      - T1499
      - T1550.002
    data_sources:
      - network_connection
      - linux
rules_count: 1
---

A missing authorization vulnerability (CWE-862) affects the `pipecat` development runner, specifically its telephony WebSocket `/ws` endpoint. An unauthenticated remote attacker who can reach an exposed `pipecat` runner can connect to this endpoint, which accepts connections without any authentication. By sending a crafted Twilio WebSocket handshake message containing an attacker-supplied `callSid` (e.g., `CAATTACKER1337INJECTED00000000001`), the attacker can trick the server. The runner will then issue an authenticated Twilio REST API hang-up request against that `callSid` using the server operator's own `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` credentials. Similar vulnerabilities exist for Telnyx and Plivo. Although designed for development and defaulting to `localhost`, `pipecat` runners are often exposed publicly via proxies for telephony provider callbacks, creating a critical attack surface for call disruption and credential abuse.

## Attack Chain

1.  An unauthenticated remote attacker identifies an exposed `pipecat` development runner with an accessible `/ws` WebSocket endpoint, typically fronted by a public proxy.
2.  The attacker establishes an unauthenticated WebSocket connection to the `/ws` endpoint on the `pipecat` runner.
3.  The attacker sends a crafted Twilio WebSocket "start" handshake message, embedding an attacker-controlled `callSid` (e.g., `CAATTACKER1337INJECTED00000000001`) into the JSON payload.
4.  The `pipecat` runner, lacking authentication checks, accepts the connection and extracts the attacker-supplied `callSid` from the handshake message without validation.
5.  When the `pipecat` pipeline terminates (e.g., via an `EndFrame` or `CancelFrame`), its `TwilioFrameSerializer` (which defaults `auto_hang_up` to `True`) automatically triggers the `_hang_up_call()` function.
6.  The `_hang_up_call()` function constructs a Twilio REST API URL, incorporating the attacker-supplied `callSid` into the endpoint (e.g., `api.twilio.com/.../Calls/{attacker_call_sid}.json`).
7.  The `pipecat` runner then uses its own configured `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` (from environment variables) to send an authenticated POST request to the constructed Twilio API URL.
8.  This POST request forcibly terminates the call associated with the attacker-supplied `callSid`, leading to denial of service or abuse of the operator's telephony account.

## Impact

This vulnerability, categorized as Missing Authorization (CWE-862), allows an unauthenticated network attacker to remotely interact with an exposed `pipecat` development runner. If the runner is configured with live Twilio, Telnyx, or Plivo credentials, the attacker can forcibly terminate active calls by injecting a known or guessed `callSid` into the WebSocket handshake. This leads to denial of service for ongoing communications and enables the attacker to abuse the organization's telephony provider credentials for unauthorized call-control actions. Organizations relying on `pipecat` for telephony integrations that have inadvertently exposed development instances to the public internet are at risk of significant operational disruption and potential compromise of their telephony accounts.

## Recommendation

*   **Review `pipecat` runner deployments**: Ensure `pipecat` development runners are strictly bound to `localhost` or internal, trusted network interfaces, and are not accessible from untrusted networks, as highlighted in the `Overview`.
*   **Network Monitoring and Blocking**: Monitor outbound connections from `pipecat` runner hosts to telephony API endpoints such as `api.twilio.com`, `api.telnyx.com`, and `api.plivo.com` (listed in IOCs), and implement network filtering or segmentation to restrict such traffic unless explicitly required and carefully configured.
*   **Detection Engineering**: Deploy the Sigma rule "Pipecat Telephony Runner Outbound Call Control Request" from this brief to your SIEM and tune it to identify anomalous outbound call termination requests originating from pipecat processes.
