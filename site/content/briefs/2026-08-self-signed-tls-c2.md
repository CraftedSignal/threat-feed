---
title: Detection of Potential C2 via Recently Issued Self-Signed TLS Certificates
slug: 2026-08-self-signed-tls-c2
description: Detection engineers can identify potential C2 activity by flagging outbound TLS connections using recently issued self-signed certificates where issuer and subject distinguished names match.
date: "2026-08-26T00:44:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - network-security
  - tls
  - threat-detection
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: C2 frameworks frequently use freshly generated self-signed certificates instead of publicly trusted CAs.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
    evidence: Identifies completed outbound TLS connections to external destinations where the server presents a recently issued, likely self-signed certificate.
    confidence_band: high
references:
  - https://www.elastic.co/security-labs/collecting-cobalt-strike-beacons-with-the-elastic-stack
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable TLS certificate metadata collection in network monitoring tools
      owner: Detection Engineering
      due: 72h
      evidence: Requires TLS certificate metadata from the Elastic network_traffic integration
  hunt_leads:
    - lead: Identify outbound TLS traffic with self-issued certificates to unknown or unauthorized external IP space
      technique_id: T1071
      data_needed:
        - TLS x509 issuer/subject DN
        - Certificate not_before date
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: C2 frameworks frequently use freshly generated self-signed certificates
  mitigation_plan:
    - priority: short_term
      action: Create exclusions for validated vendor appliances or internal development tools
      owner: IT Operations
      addresses: False positives from IoT and development servers
      evidence: Exclude known internal development egress or validated vendor destinations after review
---

Command-and-control (C2) frameworks frequently utilize freshly generated, self-signed TLS certificates to encrypt communication between compromised hosts and attacker-controlled infrastructure. Unlike publicly trusted certificates, these ephemeral credentials often share an identical issuer and subject distinguished name (DN).

This detection logic monitors outbound TLS traffic from internal network segments to external destinations. By correlating the certificate's `not_before` date (within the last 30 days) and the equality of the issuer and subject DNs, security teams can identify potentially unauthorized, custom-built C2 infrastructure that evades signature-based detection. This capability is intended to complement existing hash-based rules, such as those targeting default Cobalt Strike team-server certificates. It is highly effective for identifying rotated or unique C2 infrastructure that does not reuse known malicious certificates.

## Impact

Successful detection and investigation of these signals allow defenders to identify unauthorized outbound C2 communication. If left unmitigated, attackers can maintain persistent access and exfiltrate data from compromised internal hosts via encrypted channels. The primary risk involves the use of ephemeral, non-standard TLS configurations to bypass traditional reputation-based network filtering.

## Recommendation

- Deploy network traffic monitoring to capture TLS handshake metadata, specifically `issuer.distinguished_name`, `subject.distinguished_name`, and `not_before` timestamps.
- Prioritize the investigation of connections that exhibit a mismatch between SNI values and the presented certificate subject.
- Maintain an allowlist of known legitimate destinations that utilize self-signed certificates, such as internal development environments or authorized vendor appliances, to minimize false positives.
- Correlate alerts triggered by this logic with endpoint telemetry or existing C2 indicators to increase the confidence of incident response actions.
