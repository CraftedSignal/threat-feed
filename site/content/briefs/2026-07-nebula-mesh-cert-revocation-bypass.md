---
title: ForgeKeep Nebula-Mesh Certificate Revocation Bypass Vulnerability
slug: 2026-07-nebula-mesh-cert-revocation-bypass
description: A high-severity vulnerability, CVE-2026-61699, in ForgeKeep's nebula-mesh allows compromised or offboarded hosts to bypass certificate revocation, enabling attackers to maintain full mesh network access for up to 365 days despite operator actions.
date: "2026-07-14T20:36:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - certificate-revocation
  - network-overlay
  - defense-evasion
  - persistence
  - network
vendors:
  - ForgeKeep
products:
  - nebula-mesh (< 0.7.1)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: An attacker who exfiltrates `host.key`+`host.crt` can run stock slackhq/nebula directly, ignore the agent's 403/410 poll responses, and stay connected after the operator revokes the host.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Because the blocklist never reaches any peer's config.yml, a Blocked host retains full overlay reachability to every peer under its CA (and internal services on the mesh) for up to 30d (agent) / 365d (mobile). An attacker who exfiltrates `host.key`+`host.crt` can run stock slackhq/nebula directly, ignore the agent's 403/410 poll responses, and stay connected after the operator revokes the host.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cm26-5974-52h8
---

A significant security flaw, tracked as CVE-2026-61699, has been identified in ForgeKeep's nebula-mesh, affecting versions prior to 0.7.1. This vulnerability prevents the enforcement of certificate revocation, allowing compromised or offboarded hosts to retain full access to the Nebula mesh network. Despite the Nebula server correctly adding a host's certificate fingerprint to a per-CA blocklist and attempting to distribute this information, the agent fails to process or apply these updates. Furthermore, the configuration generator does not include the `pki.blocklist` entry in the agent's `config.yml`. This creates a critical security blind spot, as an attacker who has exfiltrated a host's key and certificate can bypass administrative revocation actions and maintain unauthorized persistence on the network for the remaining lifetime of the certificate, which can be up to 365 days for mobile hosts or 30 days for agent hosts.

## Attack Chain

1. **Initial Compromise**: An attacker successfully compromises a host within a Nebula mesh environment, gaining initial access through unrelated means (e.g., exploitation of another vulnerability or social engineering).
2. **Credential Exfiltration**: The attacker locates and exfiltrates the compromised host's Nebula client certificate (`host.crt`) and private key (`host.key`) files, which are used for authentication to the mesh.
3. **Operator Revocation Attempt**: Upon detecting the compromise or as part of a routine offboarding process, the network operator initiates a revocation action for the compromised host via the Nebula administrative UI or API.
4. **Server-Side Blocklist Update**: The Nebula server correctly processes the revocation, adds the compromised host's certificate fingerprint to its internal per-CA blocklist, and flags other agents for updates.
5. **Agent Update Failure**: Neighboring Nebula agents poll the server and receive the `blocklist` information within the `UpdatesResponse`, but due to a flaw in `internal/agent/poller.go`, they decode and then discard this blocklist without applying it to their local configuration.
6. **Configuration Generation Flaw**: Even if a configuration re-render is triggered, the `configgen` component in `internal/configgen/marshal.go` and `internal/configgen/generator.go` lacks the necessary fields to include the `pki.blocklist` entry in the generated `config.yml`.
7. **Persistence Maintained**: The attacker, using the previously exfiltrated `host.key` and `host.crt`, continues to operate the compromised host (or a clone) within the Nebula mesh, establishing connections and maintaining full overlay network reachability to all peers, completely bypassing the intended revocation.
8. **Prolonged Unauthorized Access**: The attacker retains unauthorized access for the full duration of the host's certificate validity (up to 30 days for agents and 365 days for mobile hosts), as the mesh peers continue to validate and accept the "revoked" certificate.

## Impact

The failure to enforce certificate revocation in ForgeKeep's nebula-mesh allows an already compromised host to maintain unauthorized network access and persistence despite administrative actions to block it. This means that a host, once deemed untrustworthy and revoked by an operator, can continue to communicate within the overlay network for an extended period - up to 30 days for agent hosts and 365 days for mobile hosts. An attacker who has exfiltrated the necessary certificate and key material can leverage this flaw to sustain command and control, exfiltrate data, or launch further attacks from a seemingly blocked endpoint. The operational impact is a false sense of security, as the UI/API may show a host as blocked while it retains full mesh connectivity, making it a critical bypass for defense evasion and persistence.

## Recommendation

* **Upgrade immediately**: Patch affected ForgeKeep nebula-mesh installations to version 0.7.1 or later to address CVE-2026-61699.
* **Monitor post-revocation activity**: Implement out-of-band monitoring for any network activity originating from hosts that have been administratively revoked, as they may still be active on the Nebula mesh due to CVE-2026-61699.
* **Review Nebula deployment**: Assess the integrity of all Nebula agents to ensure they are correctly updated and capable of processing and applying certificate blocklists.
* **Implement supplementary controls**: Apply additional network access controls (e.g., host-based firewalls, network segmentation) for critical services within the Nebula mesh to provide layered defense against unrevoked compromised nodes.
