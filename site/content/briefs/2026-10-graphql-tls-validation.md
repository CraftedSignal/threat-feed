---
title: TLS Validation Bypass in GraphQL Tools Legacy WebSocket Executor
slug: 2026-10-graphql-tls-validation
description: The @graphql-tools/executor-legacy-ws package incorrectly disables TLS certificate validation for WSS connections, enabling MITM attacks that can lead to credential interception.
date: "2026-10-06T00:46:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cve
  - nodejs
  - graphql
vendors:
  - GraphQL Tools
products:
  - '@graphql-tools/executor-legacy-ws (<= 1.1.34)'
  - '@graphql-tools/url-loader (< 9.1.9)'
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: This flaw allows a network-positioned attacker to perform a Man-in-the-Middle (MITM) attack against applications that use this executor with a wss:// endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-103921
    cvss: 7.4
    epss: 0.00268
references:
  - https://github.com/advisories/GHSA-6fw5-9hq8-w87g
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade @graphql-tools/executor-legacy-ws to 1.1.35 or higher and @graphql-tools/url-loader to 9.1.9 or higher.
      owner: Application Security
      due: 48h
      evidence: Patches were released in the GHSA advisory to resolve CVE-2026-103921.
  mitigation_plan:
    - priority: immediate
      action: Enforce TLS certificate validation at the infrastructure level by terminating WSS at a trusted proxy.
      owner: IT Operations
      addresses: CVE-2026-103921
      evidence: Source provided workaround for terminating TLS at a trusted proxy.
---

The package `@graphql-tools/executor-legacy-ws` contains a vulnerability (CVE-2026-103921) where the `buildWSLegacyExecutor()` function explicitly sets `rejectUnauthorized: false` for WebSocket connections. This implementation hardcodes the disabling of TLS certificate verification, effectively neutralizing the security provided by `wss://` (WebSocket Secure) endpoints. When a Node.js application uses this executor to connect to a GraphQL server, it fails to verify the server's identity.

This flaw creates an opportunity for network-positioned attackers to conduct Man-in-the-Middle (MITM) attacks. By presenting a fraudulent certificate, an attacker can decrypt the connection, intercept sensitive authentication credentials sent via `connectionParams` or headers, and manipulate subscription data in transit. This impact is limited to Node.js environments; browser-based WebSocket implementations are inherently protected as they perform their own TLS validation.

## Attack Chain

1. The target application initiates a connection to a GraphQL server using `@graphql-tools/executor-legacy-ws` via a `wss://` URI.
2. The `buildWSLegacyExecutor` function initializes the WebSocket connection with `rejectUnauthorized: false`.
3. A network-positioned attacker performs an ARP spoofing, DNS hijacking, or BGP redirection to intercept traffic destined for the GraphQL server.
4. The attacker presents an untrusted or self-signed TLS certificate to the client application.
5. The vulnerable client accepts the fraudulent certificate without error due to the disabled validation logic.
6. The client transmits authentication tokens or secrets to the attacker, believing it is communicating with the legitimate server.
7. The attacker intercepts the transmitted secrets or modifies the GraphQL subscription stream.

## Impact

Successful exploitation allows for the interception of sensitive application credentials and the manipulation of data streams within GraphQL subscriptions. This affects any backend service in the Node.js ecosystem utilizing the legacy WebSocket executor for secure communication. The scope includes any application that passes authentication tokens or session identifiers through the connection metadata.

## Recommendation

- Upgrade the vulnerable packages immediately to versions that enforce TLS validation by default: `@graphql-tools/executor-legacy-ws@1.1.35` and `@graphql-tools/url-loader@9.1.9`.
- Perform an audit of internal codebases to identify usage of `SubscriptionProtocol.LEGACY_WS` and confirm it has been updated to the non-vulnerable version.
- Implement network-layer monitoring to detect unauthorized interception or TLS inspection artifacts if immediate patching is not possible.
- Transition to the modern `graphql-ws` protocol library as a long-term architectural mitigation to avoid legacy implementation risks.
