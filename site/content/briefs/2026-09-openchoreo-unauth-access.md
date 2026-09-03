---
title: Unauthenticated API Access in OpenChoreo Cluster-Gateway
slug: 2026-09-openchoreo-unauth-access
description: OpenChoreo cluster-gateway versions prior to 1.0.2, 1.1.2, and 1.2.0 are vulnerable to unauthenticated access of management APIs on externally exposed listeners, enabling remote execution and cluster-wide compromise.
date: "2026-09-03T00:02:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:openchoreo:openchoreo:*:*:*:*:*:*:*:*
vendors:
  - OpenChoreo
products:
  - OpenChoreo cluster-gateway (< 1.0.2, >= 1.1.0, < 1.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A party able to reach the listener could therefore invoke privileged data-plane operations without authenticating and without passing through the OpenChoreo API server's authorization.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1595
    technique_name: Active Scanning
    evidence: An attacker who can reach the externally published cluster-gateway endpoint can perform data-plane operations... including... executing commands inside workload pods.
    confidence_band: high
cves:
  - id: CVE-2026-73843
    cvss: 9.6
    epss: 0.00291
references:
  - https://github.com/advisories/GHSA-qh9r-j7rp-4x2m
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade OpenChoreo cluster-gateway to 1.0.2, 1.1.2, or 1.2.0
      owner: IT Operations
      due: 24h
      evidence: Fixed in 1.0.2, 1.1.2, and 1.2.0.
  mitigation_plan:
    - priority: immediate
      action: Restrict external gateway listener access to known data-plane IPs
      owner: Network Security
      addresses: CVE-2026-73843
      evidence: 'If you cannot upgrade immediately: restrict reachability of the external gateway endpoint to known data-plane source addresses only.'
---

OpenChoreo (CVE-2026-73843) contains a critical authentication flaw in its cluster-gateway component. In multi-cluster topologies, the cluster-gateway provides an externally published endpoint to facilitate connectivity for remote data-plane agents. It was discovered that the management APIs intended for internal use were erroneously hosted on this same externally accessible network listener. Because these management APIs lacked authentication or authorization checks, any party with network reachability to the cluster-gateway endpoint can interact with privileged data-plane operations. This exposes the ability to proxy the data plane's underlying Kubernetes API and execute arbitrary commands within workload pods. The vulnerability affects versions of the OpenChoreo cluster-gateway below 1.0.2, those between 1.1.0 and 1.1.1, and the 1.2.0 release line. The vulnerability is mitigated by moving management APIs to a non-public internal listener, restricting access to the external-facing gateway to agent-connection traffic only.

## Attack Chain

1. Attacker performs network reconnaissance to identify exposed OpenChoreo cluster-gateway endpoints.
2. Attacker confirms the target is a multi-cluster deployment with an externally published listener.
3. Attacker sends unauthenticated HTTP requests to the identified management API paths on the gateway listener.
4. Attacker invokes privileged API operations intended for the OpenChoreo control-plane.
5. Attacker proxies requests to the underlying data-plane Kubernetes API.
6. Attacker leverages the proxied API access to target specific workload pods.
7. Attacker executes arbitrary commands or manipulates workloads, leading to full compromise.

## Impact

Successful exploitation leads to a complete compromise of the data-plane workloads. This includes unauthorized data disclosure, unauthorized modification of services, and potential denial of service. The impact is significant for organizations relying on OpenChoreo for multi-cluster management, as the vulnerability bypasses existing control-plane authorization, granting an unauthenticated attacker the same privileges as an authenticated internal client.

## Recommendation

Prioritized actions for addressing CVE-2026-73843:
- Upgrade OpenChoreo cluster-gateway to versions 1.0.2, 1.1.2, or 1.2.0 immediately to move management APIs to a secure internal listener.
- For deployments that cannot be patched immediately, apply firewall or network policy rules to restrict the externally published gateway endpoint to only allow traffic from authorized data-plane source addresses.
- Review ingress and network telemetry to identify unauthorized access attempts to the management API paths on the cluster-gateway listener.
