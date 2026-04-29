---
title: Cilium `cilium-bugtool` WireGuard Private Key Exposure
slug: 2026-04-cilium-wg-key-disclosure
description: The `cilium-bugtool` debugging tool in Cilium exposes WireGuard private keys, potentially allowing unauthorized access to encrypted node-to-node communication in affected versions.
date: "2026-04-26T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cilium
  - wireguard
  - key-disclosure
  - credential-access
vendors:
  - Cilium
  - Isovalent
products:
  - Cilium
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-gj49-89wh-h4gj
iocs:
  - type: email
    value: security@cilium.io
ioc_counts:
  email: 1
rules:
  - title: Detect `cilium-bugtool` Execution
    description: Detects execution of the `cilium-bugtool` command, which may indicate an attempt to gather debugging information that could contain sensitive data.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - linux
  - title: Detect `cilium sysdump` Execution
    description: Detects execution of the `cilium sysdump` command, which may indicate an attempt to gather debugging information that could contain sensitive data.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability exists in the `cilium-bugtool` utility within Cilium, an open-source networking and security platform for cloud-native environments. When used with WireGuard Transparent Encryption enabled, the tool can inadvertently include the WireGuard private key (`cilium_wg0.key`) in its output. This affects Cilium versions v1.19 between v1.19.0 and v1.19.2, v1.18 between v1.18.0 and v1.18.8, and all versions prior to v1.17.15. The exposure occurs because the tool, used for debugging and generating system dumps, collects sensitive configuration files. The vulnerability was reported and addressed by the Cilium community, with patches released in versions v1.19.3, v1.18.9, and v1.17.15. Failure to patch could lead to unauthorized decryption of network traffic.

## Attack Chain

1.  Attacker gains access to a system running a vulnerable Cilium version with WireGuard enabled, or obtains a `cilium-bugtool` archive.
2.  The `cilium-bugtool` or `cilium sysdump` command is executed, either manually by a user or an automated process (initiated by the attacker if they have access).
3.  The tool collects various debugging information, including the `cilium_wg0.key` file containing the WireGuard private key.
4.  The resulting archive is stored locally, potentially accessible to the attacker.
5.  Attacker exfiltrates the `cilium-bugtool` archive containing the WireGuard private key.
6.  The attacker uses the extracted private key to decrypt WireGuard-encrypted traffic between Cilium nodes.
7.  The attacker monitors and intercepts sensitive network communications.
8.  Attacker pivots within the cluster using the decrypted traffic to discover additional services or escalate privileges.

## Impact

Successful exploitation of this vulnerability allows an attacker to decrypt network traffic between Cilium nodes that are using WireGuard encryption. This could lead to the exposure of sensitive data, such as credentials, API keys, or proprietary information. The number of affected deployments is currently unknown, but any Cilium environment using WireGuard encryption and running a vulnerable version is at risk. The impact is significant because it compromises the confidentiality of network communications, potentially enabling further attacks and data breaches.

## Recommendation

*   Upgrade Cilium to versions v1.19.3, v1.18.9, or v1.17.15 or later to remediate CVE-2026-41520.
*   Rotate WireGuard keys on affected nodes if `cilium-bugtool` archives have been shared externally, as suggested in the advisory. Delete the `cilium_wg0.key` file and restart the Cilium agent.
*   Implement strict access control policies to limit who can execute `cilium-bugtool` or `cilium sysdump` commands, preventing unauthorized key disclosure.
*   Monitor for unusual execution of `cilium-bugtool` or `cilium sysdump` using process monitoring tools. Deploy a Sigma rule that detects unexpected execution paths.
