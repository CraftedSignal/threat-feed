---
title: Certified Address Hijacking in libp2p PeerStore
slug: 2026-09-libp2p-peer-store-hijack
description: The @libp2p/peer-store package incorrectly validates PeerRecord envelopes, allowing attackers to inject fraudulent, certified addresses into the records of victim peers.
date: "2026-09-17T19:10:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:libp2p:libp2p_peer_store:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - peer-to-peer
  - networking
  - cve-2026-86039
vendors:
  - libp2p
products:
  - '@libp2p/peer-store (>= 8.0.0, < 12.0.24)'
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The demonstrated impact is certified address poisoning and dial redirection/failure, not a full peer identity takeover.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Impact
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Attackers can poison peer-store certified address records for third-party peers.
    confidence_band: high
cves:
  - id: CVE-2026-86039
    cvss: 8.2
references:
  - https://github.com/advisories/GHSA-vrf4-mx87-p53w
action_plan:
  priority: elevated
  owners:
    - Development Teams
  immediate_actions:
    - action: Upgrade @libp2p/peer-store to 12.0.24.
      owner: Development Teams
      due: 48h
      evidence: Source advisory confirms the fix is in 12.0.24.
  mitigation_plan:
    - priority: immediate
      action: Upgrade @libp2p/peer-store to version 12.0.24 or later.
      owner: Development Teams
      addresses: CVE-2026-86039
      evidence: GHSA-vrf4-mx87-p53w
---

The `@libp2p/peer-store` package contains a critical logic error in the `consumePeerRecord` function, identified as CVE-2026-86039. The vulnerability arises because the package verifies the cryptographic signature of the `PeerRecord` envelope but fails to verify that the signer of that envelope matches the `PeerId` embedded within the payload. 

An attacker can generate a signed `PeerRecord` using their own private key but specify the `PeerId` of a victim in the payload. When processed by a vulnerable node, the library treats the payload as authentic because the envelope signature is technically valid (signed by the attacker). Consequently, the node stores attacker-controlled multiaddrs as 'certified' addresses for the victim peer. Since libp2p connection logic prioritizes certified addresses during dialing, this vulnerability allows for address-book poisoning, dial redirection, and reachability disruption. This affects `@libp2p/peer-store` versions 8.0.0 through 12.0.23.

## Attack Chain

1. Attacker generates a legitimate libp2p cryptographic key pair.
2. Attacker crafts a `PeerRecord` object containing the victim's `PeerId` and the attacker's own malicious multiaddrs.
3. Attacker signs this `PeerRecord` using their own private key, creating a valid `RecordEnvelope`.
4. Attacker transmits the forged envelope to a target node, typically through peer discovery protocols like GossipSub Peer Exchange (PX).
5. The target node's `consumePeerRecord` function extracts the `PeerId` from the envelope signature and validates the signature successfully.
6. The target node fails to compare the signer's identity against the `PeerRecord.peerId` field in the payload.
7. The target node's `peerStore.patch` method commits the forged addresses to its local datastore, marking them as `isCertified: true` under the victim's identity.
8. Future connection attempts by the target node to the victim peer are redirected to the attacker's infrastructure or result in connection failure.

## Impact

Successful exploitation results in the poisoning of the target's peer-store cache. Because certified addresses are highly prioritized by libp2p connection logic, legitimate traffic intended for the victim peer is redirected to attacker-controlled endpoints. This can disrupt network connectivity, prevent legitimate peer communication, and facilitate further reconnaissance or man-in-the-middle attacks on the application layer. Thousands of decentralized applications and infrastructure nodes relying on libp2p for peer-to-peer networking are potentially affected.

## Recommendation

Prioritized, concrete actions for engineering and security teams:
- Upgrade `@libp2p/peer-store` to version 12.0.24 or later to implement the required PeerId/signer identity invariant.
- Audit existing PeerStore datastores for unexpected or unauthorized certified addresses associated with high-value peer IDs if the node has been exposed to untrusted peer records.
- Implement strict peer-to-peer connection validation logic to ensure that connection upgrades and identity handshakes are not solely reliant on certified peer records stored in the local cache.
