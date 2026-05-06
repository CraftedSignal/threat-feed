---
title: OpenTelemetry Collector Azure Auth Extension Authentication Bypass
slug: 2026-05-otel-auth-bypass
description: 'A server-side authentication bypass vulnerability exists in opentelemetry-collector-contrib''s azureauthextension versions 0.124.0 through 0.150.0, allowing attackers with a valid Azure access token to authenticate to any OpenTelemetry receiver that uses `auth: azure_auth` due to improper JWT validation.'
date: "2026-05-07T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - opentelemetry
  - azure
  - jwt
vendors:
  - Microsoft
  - GitHub
  - OpenTelemetry
products:
  - opentelemetry-collector-contrib
  - azureauthextension
  - Entra ID
  - go-oidc
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-pjv4-3c63-699f
  - https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/39178
rules:
  - title: Detect OpenTelemetry Azure Auth Bypass Attempt
    description: Detects attempts to exploit the OpenTelemetry Azure Auth bypass vulnerability by monitoring for suspicious Host headers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1588.003
    data_sources:
      - webserver
      - linux
  - title: Detect OpenTelemetry Azure Auth Bypass Attempt (gRPC)
    description: Detects attempts to exploit the OpenTelemetry Azure Auth bypass vulnerability by monitoring for suspicious :authority headers in gRPC requests, which surface as Host.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1588.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `azureauthextension` in `opentelemetry-collector-contrib` versions 0.124.0 through 0.150.0 contains a server-side authentication bypass. The `Authenticate` method doesn't validate incoming bearer tokens as JWTs, leading to a vulnerability where any party holding a valid Azure access token can authenticate to any OpenTelemetry receiver using `auth: azure_auth`. The extension compares client tokens to its own minted tokens via string equality, using the client-supplied `Host` header to determine the token scope. An attacker can replay tokens minted for any Azure resource the service principal has a token for, by setting the `Host` header, which compromises authentication. This issue was introduced in PR #39178 and is present in versions v0.124.0 through v0.150.0.

## Attack Chain

1. Attacker obtains a valid Azure access token for the collector's service principal (SP) from a co-tenant workload, compromised peer, or leaked `Authorization:` header.
2. Attacker crafts an HTTP or gRPC request to an OpenTelemetry receiver configured with `azureauthextension`.
3. Attacker sets the `Authorization` header in the request to "Bearer " followed by the obtained Azure access token.
4. If exploiting the scope confusion variant, the attacker sets the `Host` header to match the Azure resource associated with the token (e.g., `vault.azure.net` for a Key Vault token).
5. The `azureauthextension`'s `Authenticate` method extracts the `Authorization` and `Host` headers.
6. The `getTokenForHost` function uses the client-supplied `Host` header to request a token for the corresponding scope (e.g., `https://vault.azure.net/.default`).
7. The extension performs a string comparison between the client-supplied token and the server-minted token, which succeeds because both tokens are valid for the same service principal and scope.
8. The attacker successfully bypasses authentication and ingests arbitrary telemetry data (traces, metrics, and logs) into the OpenTelemetry collector.

## Impact

Successful exploitation allows unauthenticated ingestion of arbitrary traces, metrics, and logs. This can lead to telemetry-backend poisoning, log injection (masking real attacker activity), metric manipulation to trigger or suppress alerts, cost-amplification against pay-per-datapoint backends, and adversarial traces that corrupt service-graph and incident-triage signals. Multi-workload Azure environments, deployments that forward `Authorization:` headers, and multi-tenant environments are most at risk. This vulnerability affects operators of `opentelemetry-collector-contrib` v0.124.0 through v0.150.0 who have configured `azureauthextension` on a receiver's `auth:` block.

## Recommendation

- As an immediate mitigation, remove `azure_auth` from any receiver `auth:` blocks. This prevents the vulnerable authentication mechanism from being used.
- Deploy the Sigma rule `Detect OpenTelemetry Azure Auth Bypass Attempt` to detect attempts to exploit this vulnerability by monitoring for specific HTTP `Host` header values associated with Azure services.
- Implement JWT validation using `oidcauthextension` pointed at the tenant discovery URL, with audience pinned from configuration, as described in the mitigation section.
- Upgrade to a patched version of `opentelemetry-collector-contrib` once available.
