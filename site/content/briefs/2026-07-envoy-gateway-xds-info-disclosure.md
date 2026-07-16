---
title: Envoy Gateway xDS Control Plane Information Disclosure Vulnerability (CVE-2026-53714)
slug: 2026-07-envoy-gateway-xds-info-disclosure
description: A vulnerability in Envoy Gateway, when operating in GatewayNamespaceMode, allows unauthenticated access to the xDS gRPC server on port 18000. This is due to a missing unary interceptor and an authentication bypass in the JWT interceptor that fails to validate specific message types (DiscoveryRequest). Any pod within the cluster can exploit this flaw using the State-of-the-World (SotW) xDS protocol to retrieve sensitive information, including TLS private keys, all xDS resources, backend endpoints, and routing rules.
date: "2026-07-16T19:33:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - information-disclosure
  - cloud
  - network
vendors:
  - Envoyproxy
products:
  - Envoy Gateway (versions before 1.7.4)
  - Envoy Gateway (versions 1.8.0-rc.0 through 1.8.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: TLS private keys via StreamSecrets (SDS)
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Local System
    evidence: All xDS resources via StreamAggregatedResources (ADS), Backend endpoints via StreamClusters / StreamEndpoints (CDS/EDS), Routing rules via StreamRoutes / StreamListeners (RDS/LDS)
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-22xc-xg2r-9j7v
---

Envoy Gateway versions prior to 1.7.4 and versions 1.8.0-rc.0 through 1.8.0 are susceptible to an information disclosure vulnerability, CVE-2026-53714, when deployed in `GatewayNamespaceMode` (`provider.kubernetes.deploy.type=GatewayNamespace`). This flaw stems from an incomplete implementation of authentication within the xDS gRPC server. Specifically, the server lacks a unary interceptor and its JWT authentication interceptor incorrectly bypasses validation for `discoveryv3.DiscoveryRequest` messages, which are part of the State-of-the-World (SotW) xDS protocol. This oversight allows any unauthenticated pod within the Kubernetes cluster that can reach the xDS server on port 18000 to access sensitive configuration data, including TLS private keys, all xDS resources (ADS), backend service endpoints (CDS/EDS), and routing rules (RDS/LDS). The vulnerability has been reported by @dashingDragon and @Donjon-Cerberus.

## Attack Chain

1. A malicious pod or compromised application within the Kubernetes cluster identifies the Envoy Gateway xDS server listening on port 18000.
2. The attacker establishes a gRPC connection to the xDS server without providing any authentication credentials.
3. The attacker crafts a `discoveryv3.DiscoveryRequest` message to leverage the State-of-the-World (SotW) xDS protocol.
4. The Envoy Gateway's JWT authentication interceptor, configured for `GatewayNamespaceMode`, fails to validate this specific message type, bypassing any authentication checks.
5. The xDS server processes the unauthenticated `DiscoveryRequest` successfully due to the missing unary interceptor and the authentication bypass.
6. The attacker then requests sensitive xDS resources, including TLS private keys via StreamSecrets (SDS), aggregated xDS resources via StreamAggregatedResources (ADS), backend endpoints via StreamClusters/StreamEndpoints (CDS/EDS), and routing rules via StreamRoutes/StreamListeners (RDS/LDS).
7. The Envoy Gateway xDS server responds to the unauthenticated request, disclosing critical configuration data to the attacker.

## Impact

Successful exploitation of CVE-2026-53714 leads to unauthenticated information disclosure of highly sensitive data. Attackers can gain access to TLS private keys, which could be used to decrypt encrypted traffic, impersonate services, or enable further attacks. Disclosure of xDS resources, backend endpoints, and routing rules provides a comprehensive understanding of the cluster's network topology and service configurations, allowing attackers to plan sophisticated follow-on attacks, redirect traffic, or achieve persistent access. This vulnerability affects any organization using Envoy Gateway in `GatewayNamespaceMode` within a Kubernetes environment, potentially exposing core infrastructure secrets and network configurations.

## Recommendation

* Patch CVE-2026-53714 immediately by upgrading Envoy Gateway to a non-vulnerable version (e.g., 1.7.4 or later, or 1.8.1 or later) as referenced in the GHSA advisory.
* Implement strict network segmentation and access controls within your Kubernetes clusters to restrict access to the Envoy Gateway xDS server on port 18000, ensuring only authorized components can connect.
* Monitor network connection logs for any suspicious or unauthorized access attempts to Envoy Gateway's xDS server on port 18000 from unexpected sources or without proper authentication.
