---
brief_id: brief-2026-11-10-telepresence-tunnel-hijack
event_id: brief-2026-11-10-telepresence-tunnel-hijack
revision: 1
activity_at: "2026-11-10T10:17:33Z"
title: 'Telepresence: Traffic Manager session hijacking via unauthenticated Tunnel endpoint (CVE-2026-102339)'
slug: 2026-11-telepresence-tunnel-hijack
description: The Telepresence Traffic Manager fails to verify ownership of session IDs in the Tunnel gRPC endpoint, allowing attackers to hijack active client sessions and gain unauthorized access to network routing contexts.
date: "2026-11-10T10:17:33Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of gRPC traffic monitoring
cpes:
  - cpe:2.3:a:telepresence:telepresence:*:*:*:*:*:*:*:*
vendors:
  - Telepresence
products:
  - Telepresence (v2 < 2.31.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Combined with the unauthenticated ArriveAsClient endpoint, an attacker can create their own sessions and pivot to impersonate active developer sessions.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Traffic Manager routes tunnel traffic for victimSessionID through this attacker-controlled bidirectional stream
    confidence_band: high
cves:
  - id: CVE-2026-102339
    cvss: 8.2
    epss: 0.00287
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-6j3h-rp73-6rvf
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Telepresence Traffic Manager to 2.31.0
      owner: IT Operations
      due: 24h
      evidence: Vulnerability addressed in version 2.31.0
  hunt_leads:
    - lead: Identify unauthorized access to the Traffic Manager gRPC service (default 8081) from non-standard internal IPs
      technique_id: T1190
      data_needed:
        - Kubernetes ingress/egress logs
        - Service mesh (Istio/Linkerd) access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The Tunnel endpoint accepts a session ID... with no ownership proof
  mitigation_plan:
    - priority: immediate
      action: Upgrade Telepresence to v2.31.0
      owner: IT Operations
      addresses: CVE-2026-102339
      evidence: GHSA advisory specifies version 2.31.0 as the fix
---

The Traffic Manager `Tunnel` gRPC streaming endpoint in Telepresence accepts a session ID from the initial client-controlled message payload without verifying the caller's identity. This allows an attacker to supply an active session ID and receive a fully functional tunnel, gaining the network routing capabilities of the associated legitimate client. The issue is exacerbated by the lack of authentication on the `ArriveAsClient` endpoint, which allows attackers to generate their own valid session IDs. The vulnerability affects Telepresence versions prior to 2.31.0.

## Attack Chain

1. Attacker establishes a connection to the Traffic Manager gRPC service (often exposed on port 8081).
2. Attacker invokes the `ArriveAsClient` endpoint to generate a session or harvests an existing session ID via log leakage.
3. Attacker initializes a `Tunnel` bidirectional gRPC stream.
4. Attacker sends a `TunnelMessage` payload containing the target victim session ID.
5. Traffic Manager processes the message in `state.Tunnel` and associates the attacker's stream with the victim's session in the internal map.
6. Attacker gains the ability to intercept or inject traffic into the victim's network routing context.

## Impact

Successful exploitation allows an attacker to impersonate a legitimate developer session within a cluster. This grants the attacker the same network routing capabilities as the victim, enabling unauthorized access to cluster-internal resources or network paths reachable by the Telepresence client.

## Recommendation

- Upgrade the Telepresence Traffic Manager to version 2.31.0 or later immediately to incorporate session ownership verification.
- Audit cluster-internal network access to the Traffic Manager gRPC service to ensure only authorized clients can reach the endpoint.
- Review centralized logging for any instances where `ArriveAsClient` or `Tunnel` endpoints are being accessed by unexpected or non-standard client service accounts.
