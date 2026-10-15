---
title: Unauthenticated Administrative API Exposure in Dgraph Zero
slug: 2026-10-dgraph-zero-unauth-admin
description: Dgraph versions up to 25.3.8 expose an unauthenticated HTTP administrative API on port 6080, allowing remote attackers to perform unauthorized cluster membership operations and cause denial of service.
date: "2026-10-15T22:23:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:dgraph:dgraph:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - dgraph
vendors:
  - Dgraph
products:
  - Dgraph (<= 25.3.8)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An unauthenticated request to /removeNode... breaks the Zero control plane.
    confidence_band: high
cves:
  - id: CVE-2026-102748
references:
  - https://github.com/advisories/GHSA-qj98-gp63-54xj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102748
rules:
  - title: Detect CVE-2026-102748 Exploitation - Unauthenticated Zero API Access
    description: Detects unauthorized attempts to access sensitive Dgraph Zero administrative endpoints, which indicate potential exploitation of CVE-2026-102748.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block external network access to TCP port 6080 for all Dgraph Zero instances.
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated administrative API exposure on port 6080.
  hunt_leads:
    - lead: Search logs for HTTP GET requests to /removeNode, /assign, or /moveTablet.
      technique_id: T1498
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: These routes were identified as unauthenticated and destructive.
  mitigation_plan:
    - priority: immediate
      action: Set disable-admin-http=true in Zero configuration.
      owner: IT Operations
      addresses: CVE-2026-102748
      evidence: The issue exists because Zero administrative HTTP endpoints are registered directly.
---

Dgraph versions up to and including 25.3.8 contain a critical vulnerability in the Zero control plane component. The service registers administrative HTTP endpoints - such as `/state`, `/assign`, and `/removeNode` - directly on port 6080 without implementing any authentication or IP-based access control. By default, the `disable-admin-http` configuration flag is set to `false`, making these endpoints accessible to any entity with network reachability to the port.

This vulnerability allows unauthenticated remote actors to query cluster metadata and topology information. Furthermore, attackers can invoke state-changing administrative operations, specifically the `/removeNode` endpoint. Successful exploitation of this endpoint triggers destructive cluster membership changes, leading to a permanent denial of service for the Zero control plane and causing connected Alpha nodes to fail due to lost connectivity to the control plane. Organizations using Dgraph should prioritize restricting access to port 6080 to trusted internal management networks only.

## Attack Chain

1. Attacker performs network discovery to identify accessible services on port 6080.
2. Attacker sends an unauthenticated HTTP GET request to `/state` to enumerate cluster topology, node IDs, and leader status.
3. Attacker sends an unauthenticated HTTP GET request to `/assign` to interact with node allocation and control plane functionality.
4. Attacker identifies a target node ID and group ID via the information gathered in step 2.
5. Attacker sends a malicious HTTP GET request to `/removeNode?id=[ID]&group=[GROUP]` to initiate the peer removal process.
6. Zero control plane processes the request, invoking `Server.RemoveNode` and `ProposePeerRemoval` without authorization validation.
7. The target node is removed from the cluster topology, causing the Zero control plane to crash or enter an unstable state.
8. Dependent Alpha nodes fail to reconnect to the Zero control plane, resulting in a persistent denial of service.

## Impact

The vulnerability allows unauthenticated remote attackers to perform unauthorized administrative actions against the Dgraph Zero control plane. This leads to information disclosure regarding cluster topology and facilitates a persistent denial of service (DoS) by destabilizing cluster membership. The impact is significant for production environments, as it renders the Dgraph deployment unusable until manual intervention and control plane recovery are performed.

## Recommendation

* Immediately restrict network access to port 6080, ensuring it is not exposed to the public internet or untrusted network segments.
* Update Dgraph installations to a patched version beyond 25.3.8 once available from the vendor.
* Monitor webserver logs for unauthorized HTTP GET requests directed at sensitive endpoints: `/state`, `/assign`, `/removeNode`, and `/moveTablet`.
* Configure `disable-admin-http=true` in the Dgraph Zero configuration if administrative HTTP capabilities are not strictly required for current operations.
