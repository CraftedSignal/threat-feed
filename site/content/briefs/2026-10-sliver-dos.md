---
title: Sliver Unauthenticated Memory Exhaustion DoS in PNG Decoder
slug: 2026-10-sliver-dos
description: Sliver is vulnerable to a denial-of-service attack due to a lack of size constraints during PNG image decoding in its HTTP(S) listener, allowing unauthenticated attackers to exhaust server memory.
date: "2026-10-15T22:27:33Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - BishopFox
tags:
  - denial-of-service
  - vulnerability
  - c2-infrastructure
vendors:
  - BishopFox
products:
  - Sliver
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This vulnerability lets the attacker completely max out the RAM of the machine running server, leading to a complete loss of availability.
    confidence_band: high
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Restrict network access to Sliver C2 listener ports to authorized IP ranges.
      owner: SOC
      due: 24h
      evidence: Unauthenticated nature of the DoS allows any network-connected actor to exploit the listener.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest patched version of Sliver.
      owner: IT Operations
      addresses: Sliver vulnerability in PNG decoder
      evidence: Patching is required to introduce input validation for image dimensions.
---

Sliver contains an unauthenticated denial-of-service (DoS) vulnerability within its HTTP(S) listener. The issue stems from the server-side PNG decoder, which lacks validation or constraints on the dimensions and resulting pixel data of incoming image files. By submitting a specially crafted, maliciously large PNG file to the listener, an attacker can trigger excessive memory allocation during the `image.Decode` and `png.Decode` processes. This process results in rapid RAM consumption, ultimately leading to process termination or complete service exhaustion. The vulnerability is further complicated by the use of predictable nonces in the Sliver protocol, which simplifies the identification of active listener endpoints. This vulnerability poses a significant risk to the availability of C2 infrastructure if exposed to untrusted network segments.

## Attack Chain

1. Attacker identifies an exposed Sliver HTTP(S) listener port (e.g., 8080).
2. Attacker crafts a malicious PNG file with extreme width and height dimensions (e.g., 32,767x32,767 pixels).
3. Attacker uses a tool to systematically probe the listener for nonce requirements or direct delivery if the protocol allows.
4. Attacker sends an HTTP POST request containing the crafted PNG file payload to the Sliver listener.
5. The Sliver server's HTTP(S) listener receives the binary data.
6. The `server/encoders/encoders.go` and `util/encoders/images.go` logic initiates a `png.Decode` operation on the malicious payload.
7. The server attempts to allocate the buffer required for the uncompressed image, consuming all available system memory.
8. The Sliver server crashes or stops responding, resulting in a successful DoS.

## Impact

Successful exploitation results in a complete denial-of-service of the Sliver C2 server. This prevents operators from maintaining command and control of implants, effectively severing communications with all connected agents. Because the exploit is unauthenticated, any internet-facing Sliver listener is potentially subject to this memory exhaustion attack, risking both operational disruption and potential forensic exposure during the crash state.

## Recommendation

* Upgrade the Sliver server to the latest patched version immediately to ensure that input validation is applied to image decoding routines.
* Restrict access to Sliver HTTP(S) listeners to trusted source IPs via firewall or network access control lists (ACLs).
* Monitor HTTP traffic targeting Sliver listeners for anomalous POST requests containing binary payloads that deviate from expected C2 heartbeat patterns.
* Implement memory limits on the container or host environment running the Sliver server to mitigate the impact of OOM (Out-of-Memory) conditions.
