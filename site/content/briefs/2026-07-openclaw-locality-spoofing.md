---
title: OpenClaw Control UI Locality Spoofing Vulnerability
slug: 2026-07-openclaw-locality-spoofing
description: An authentication bypass vulnerability (CVE-2026-53817) in OpenClaw's Control UI pairing mechanism allows an attacker with existing network/authentication foothold in LAN/shared-token deployments to spoof locality information, leading to the acquisition of a durable admin-capable device token that grants persistent administrative access, even after shared gateway tokens are rotated.
date: "2026-07-03T12:16:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:node.js:*:*
tags:
  - authentication
  - vulnerability
  - admin-access
  - persistence
  - network
products:
  - openclaw (< 2026.5.22)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: a caller could ... obtain a durable admin-capable device token. That token could remain useful after the shared gateway token was rotated
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: obtain a durable admin-capable device token
    confidence_band: high
cves:
  - id: CVE-2026-53817
    cvss: 8.8
    epss: 0.00309
references:
  - https://github.com/advisories/GHSA-chr9-m4q2-76hw
---

A high-severity authentication bypass vulnerability, identified as CVE-2026-53817, exists in `openclaw` versions prior to `2026.5.22`. This flaw affects deployments leveraging LAN-bound gateways or shared-token Control UI access, where locality signals are implicitly trusted during the pairing process. An attacker who has already established network or authentication foothold to reach the Control UI pairing path can exploit this vulnerability. By spoofing specific locality information, the attacker can trick the system into issuing a durable admin-capable device token. This token provides persistent administrative access, which remains valid even after the initial temporary or shared gateway tokens are rotated. This poses a significant risk as it allows unauthorized, long-term administrative control over affected OpenClaw instances.

## Attack Chain

1.  An attacker gains an initial network or authentication foothold, enabling them to access the OpenClaw Control UI pairing path.
2.  The attacker initiates a device pairing request to the vulnerable OpenClaw Control UI instance.
3.  During the pairing process, the attacker crafts and sends requests that include spoofed or manipulated locality information.
4.  The vulnerable OpenClaw Control UI, versions prior to `2026.5.22`, improperly validates these spoofed locality signals.
5.  Due to the misinterpretation of the locality signals, the OpenClaw instance grants the attacker a durable admin-capable device token.
6.  The attacker utilizes this newly acquired durable device token to establish and maintain persistent administrative access to the Control UI.
7.  This persistent access remains effective even if the original temporary or shared gateway tokens, which might have initially granted the attacker their foothold, are subsequently revoked or rotated.

## Impact

Successful exploitation of CVE-2026-53817 can lead to persistent administrative control over affected OpenClaw Control UI instances. The primary observed damage is the ability to transform temporary or shared access into a long-lasting, unauthorized administrative presence. While the specific number of victims or targeted sectors is not provided, any organization utilizing `openclaw` in LAN/shared-token configurations is at risk. If exploited, an attacker gains full administrative capabilities, potentially leading to unauthorized configuration changes, data manipulation, or further compromise of integrated systems managed by the Control UI. The durable nature of the token means access persists even after initial entry vectors are mitigated.

## Recommendation

*   **Patch CVE-2026-53817**: Immediately upgrade affected `openclaw` installations to version `2026.5.22` or later to remediate CVE-2026-53817.
*   **Implement Network Segmentation**: Ensure that Control UI pairing paths are not exposed on networks accessible to untrusted clients, as described in the summary.
*   **Review Paired Devices**: For older deployments, regularly review and remove any unexpected or unauthorized paired devices from the Control UI configuration.
