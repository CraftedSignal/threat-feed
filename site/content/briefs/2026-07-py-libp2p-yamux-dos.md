---
title: py-libp2p yamux Connection DoS via Oversized Data Frame
slug: 2026-07-py-libp2p-yamux-dos
description: A denial-of-service vulnerability in py-libp2p versions up to 0.6.0 allows an authenticated attacker to send a specially crafted 12-byte DATA or SYN frame with an oversized length field, causing the victim's yamux read loop to block indefinitely and freezing all streams on the affected connection.
date: "2026-07-24T22:38:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - network
  - python
  - libp2p
vendors:
  - libp2p
products:
  - py-libp2p (<= 0.6.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
    evidence: A single authenticated peer (one that has completed the noise handshake, which requires no credentials) can permanently freeze the yamux read loop for a given connection using 12 bytes of payload. All streams on that connection stop working.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-hmj8-5xmh-5573
---

A high-severity denial-of-service vulnerability, tracked as GHSA-hmj8-5xmh-5573, has been identified in the `py-libp2p` library, specifically affecting versions up to 0.6.0. The vulnerability resides in the `yamux` stream multiplexer's handling of incoming DATA and SYN frames. After completing a standard libp2p noise handshake, an authenticated peer can send a malicious 12-byte `yamux` frame that specifies an oversized body length (e.g., 4 GB). Due to a lack of validation against the stream's receive window and the absence of a per-frame timeout, the victim's `yamux` read loop (`handle_incoming()`) attempts to read the specified enormous amount of data indefinitely. This permanently blocks the connection, making all streams on it unresponsive and causing a denial of service without raising exceptions or logging errors. This issue affects the default `new_host()` configuration, making a broad range of `py-libp2p` deployments vulnerable.

## Attack Chain

1. Attacker and victim `py-libp2p` nodes establish a connection and complete a standard libp2p noise handshake for secure communication.
2. The two nodes then negotiate and establish a `yamux` multiplexed connection over the secured channel.
3. The attacker crafts a malicious 12-byte `yamux` frame with `version=0x00`, `type=DATA` (or `SYN`), `flags=0x0000`, `stream_id=1`, and a `length` field set to `0xFFFFFFFF` (4,294,967,295 bytes).
4. The attacker writes this crafted 12-byte frame directly to the `secured_conn` (the encrypted channel).
5. The victim's `yamux` multiplexer receives and decrypts the frame, then its `handle_incoming()` method reads the 12-byte header.
6. The `handle_incoming()` method dispatches the frame based on its `TYPE_DATA` (or `SYN`) and subsequently calls `read_exactly()` with the malformed 4 GB length value.
7. Because the attacker sends only the 12-byte header and no actual data matching the declared 4 GB length, `read_exactly()` enters an indefinite blocking state, waiting for data that will never arrive.
8. This permanent block freezes the entire `handle_incoming()` loop for that `yamux` connection, rendering all streams on it unusable, effectively achieving a denial of service.

## Impact

The vulnerability allows any authenticated peer to completely freeze a `yamux` connection using a mere 12-byte payload, resulting in a denial of service. All existing and future streams on the affected connection become unresponsive, preventing any further communication. This attack does not raise exceptions, generate error logs, or trigger any automatic recovery mechanisms, leading to a persistent DoS. Since the default `new_host()` configuration for `py-libp2p` is affected, a large number of deployments are vulnerable. An attacker could target multiple nodes, potentially freezing all their active connections if they exhaust the default connection limit (e.g., 10,000 connections using approximately 120 KB of total traffic). The impact is limited to availability, with no observed confidentiality or integrity compromise.

## Recommendation

* Update `py-libp2p` to version 0.6.1 or later to apply the official patch for GHSA-hmj8-5xmh-5573, which includes receive window validation and per-frame timeouts.
* Implement the proposed remediation of enforcing the receive window on inbound DATA frames before calling `read_exactly()` in `libp2p/stream_muxer/yamux/yamux.py`.
* Apply the proposed remediation of adding a per-frame timeout within the `handle_incoming()` loop for `yamux` frames in `libp2p/stream_muxer/yamux/yamux.py` to prevent indefinite blocking.
