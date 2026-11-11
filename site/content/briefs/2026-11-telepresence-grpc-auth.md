---
brief_id: brief-2026-11-11-telepresence-grpc-auth
event_id: brief-2026-11-11-telepresence-grpc-auth
revision: 1
activity_at: "2026-11-11T02:06:12Z"
title: 'Telepresence: Traffic Manager gRPC authentication bypass (CVE-2026-102340)'
slug: 2026-11-telepresence-grpc-auth
description: The Telepresence Traffic Manager gRPC API lacks authentication, allowing any pod with network access to intercept services and exfiltrate secrets from unauthorized Kubernetes namespaces.
date: "2026-11-11T02:06:12Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:telepresence:telepresence:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - kubernetes
  - telepresence
  - cve-2026-102340
vendors:
  - Telepresence
products:
  - Telepresence (< 2.31.0)
cves:
  - id: CVE-2026-102340
    cvss: 8.5
    epss: 0.00281
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-j8j4-rw65-56r6
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Platform Engineering
  immediate_actions:
    - action: Upgrade Telepresence Traffic Manager to 2.31.0 or later
      owner: Platform Engineering
      due: 24h
      evidence: Telepresence (< 2.31.0) is marked vulnerable
  hunt_leads:
    - lead: Identify unauthorized access to the Traffic Manager gRPC port
      technique_id: T1552.001
      data_needed:
        - Kubernetes Network Policy logs
        - Traffic Manager container logs (gRPC method calls)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Any pod with cluster network access can connect to the unsecured gRPC API
  mitigation_plan:
    - priority: immediate
      action: Deploy NetworkPolicies to limit access to traffic-manager:8081
      owner: Platform Engineering
      addresses: CVE-2026-102340
      evidence: The API is unprotected and relies on cluster network reachability
---

The Telepresence Traffic Manager (port 8081) exposes a gRPC API that fails to verify the identity of connecting clients or enforce authorization constraints. Any pod within the cluster network can register as a client and initiate service interceptions against managed namespaces. Because the service performs no Kubernetes Service Account token validation or RBAC checks during registration (ArriveAsClient) or interception (CreateIntercept), an attacker can redirect traffic and capture the full container environment of victim services, including secrets and API keys mounted as environment variables. This vulnerability affects Telepresence versions prior to 2.31.0.

## Impact
Successful exploitation allows unauthorized cross-namespace access to service traffic and pod environment secrets. In default cluster-wide deployments where the Traffic Manager manages all namespaces, the entire cluster is exposed to potential credential theft and traffic interception.

## Recommendation
- Upgrade Telepresence to version 2.31.0 or later immediately.
- Audit Kubernetes Network Policies to restrict access to the Traffic Manager service (port 8081) to only trusted client namespaces.
- Review Telepresence Traffic Manager logs for suspicious `ArriveAsClient` or `CreateIntercept` calls originating from non-authorized pods or unexpected namespaces.
