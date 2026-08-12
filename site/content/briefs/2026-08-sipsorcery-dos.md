---
title: SIPSorcery Denial of Service via SCTP SACK Chunk OOB Read
slug: 2026-08-sipsorcery-dos
description: The SIPSorcery library is vulnerable to a denial of service via a crafted SCTP SACK chunk that causes an out-of-bounds read and subsequent termination of the SCTP receive thread.
date: "2026-08-12T22:48:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - SIPSorcery
products:
  - SIPSorcery
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A single crafted SACK chunk from a negotiated WebRTC peer forces reads past the end of the 262144-byte receive buffer, raising IndexOutOfRangeException, which is not caught by the recoverable handler and terminates the dedicated SCTP receive thread.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade SIPSorcery to the latest version resolving this vulnerability.
      owner: IT Operations
      due: 72h
      evidence: SIPSorcery <= 10.0.13 is vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Monitor service stability for unexpected thread termination of SCTP receive tasks.
      owner: IT Operations
      addresses: Permanent DoS via SCTP association loss.
      evidence: Dedicated SCTP receive thread is terminated permanently upon exception.
---

SIPSorcery versions 10.0.13 and earlier are susceptible to a permanent denial of service condition in the SCTP stack. The `SctpSackChunk.ParseChunk` method reads the `numGapAckBlocks` and `numDuplicateTSNs` counts directly from an attacker-controlled SCTP SACK chunk without validating these values against the actual length of the receive buffer. 

By providing specifically crafted values, an attacker can force the application to perform reads past the boundary of the 262144-byte receive buffer. This operation triggers an `IndexOutOfRangeException`. Because the library handles this exception using a generic catch block that breaks the receive loop rather than a recoverable handler, the dedicated SCTP receive thread is terminated and fails to restart. This results in the immediate and permanent loss of the SCTP association and all associated WebRTC data channels.

## Attack Chain

1. An attacker establishes a post-DTLS negotiated WebRTC connection with a target running a vulnerable SIPSorcery version.
2. The attacker constructs a malicious SCTP packet containing a SACK chunk (type 3).
3. The attacker sets the `chunkLength` to a valid value (e.g., 16) to pass initial `SctpPacket.ParseChunks` sanity checks.
4. The attacker sets `numGapAckBlocks` to 0xFFFF, forcing the parser into an oversized iteration loop.
5. The attacker computes a valid CRC32C checksum to bypass the network-level verification stage of the SCTP packet.
6. The SIPSorcery library reads the crafted count into the gap-ack processing loop within `SctpSackChunk.ParseChunk`.
7. The loop accesses index 262144 of the 262144-byte buffer, triggering an `IndexOutOfRangeException`.
8. The exception propagates to the generic `catch` block in `RTCSctpTransport.DoReceive`, which executes a `break` statement and permanently terminates the receive thread.

## Impact

The vulnerability results in a complete and permanent denial of service for any affected SCTP association. All data channels associated with the connection are dropped and the service cannot recover without a manual restart of the impacted thread or service, depending on implementation. This impacts all applications utilizing SIPSorcery for WebRTC transport.

## Recommendation

Detection and mitigation should focus on identifying malformed SCTP traffic or application-level thread stability.

* Update SIPSorcery to a patched version that implements bounds checking for `numGapAckBlocks` and `numDuplicateTSNs`.
* Implement application-level monitoring for the termination of the `_receiveThread` in `RTCSctpTransport`.
* If patching is not immediate, deploy network security controls to inspect and drop SCTP packets with suspicious chunk parameters if the environment supports deep packet inspection for WebRTC protocols.
