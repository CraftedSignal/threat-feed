---
title: Russh CryptoVec Unchecked Allocation Vulnerability
slug: 2026-05-russh-cryptovec-vuln
description: Russh versions up to 0.60.2 are vulnerable to a memory-safety hardening issue due to unchecked `CryptoVec` allocation and growth handling, reachable from local agent inputs and remote SSH traffic, potentially triggering a process abort under constrained memory conditions.
date: "2026-05-21T20:50:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - memory-allocation
  - denial-of-service
  - ssh
  - CVE-2026-46673
products:
  - russh (<= 0.60.2)
  - russh-cryptovec (<= 0.60.2)
references:
  - https://github.com/advisories/GHSA-g9f8-wqj9-fjw5
  - CVE-2026-46673
rules:
  - title: Detect Russh CryptoVec Memory Allocation Failure
    description: Detects potential memory allocation failures in Russh's CryptoVec component by monitoring for specific error messages.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-46673
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
  - title: Detect Russh Oversized Agent Frame
    description: Detects Russh agent connections with oversized frames, which could be indicative of CVE-2026-46673 exploitation.
    platform: sigma
    severity: low
    tactics:
      - cve-2026-46673
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Russh versions up to 0.60.2 contain a vulnerability related to unchecked memory allocation within the `CryptoVec` component. This flaw stems from insufficient validation of peer-supplied lengths when resizing buffers, leading to potential unchecked capacity growth, length arithmetic, and unsafe allocation/locking paths. In current releases, local SSH agent peers can trigger this through crafted frame lengths. In older releases before version 0.58.0, remote SSH traffic could also exploit this via transport and compression buffers. Successful exploitation can lead to a process abort, especially under constrained memory conditions, impacting the availability of the SSH service. The vulnerability is identified as CVE-2026-46673.

## Attack Chain

1. An attacker connects to an SSH server running a vulnerable version of Russh (<= 0.60.2).
2. If the Russh version is before 0.58.0, the attacker sends a crafted SSH packet with a large, compressed payload.
3. The server attempts to decompress the payload, leading to the allocation of a `CryptoVec` buffer for the decompressed data.
4. Due to the unchecked growth, the `CryptoVec` attempts to allocate an excessively large buffer, potentially exceeding available memory.
5. Under constrained memory conditions, the allocation fails, resulting in a null pointer being passed to `NonNull::new_unchecked()`.
6. This triggers a panic and aborts the process.
7. Alternatively, if the attacker has local access to an SSH agent client or server, they can send oversized agent frame lengths.
8. The agent client or server attempts to resize its internal buffer based on the attacker-controlled length, triggering the same unchecked allocation issues described above, leading to a process abort.

## Impact

This vulnerability can lead to a denial-of-service condition. While the provided information doesn't demonstrate practical code execution or data breaches, the vulnerability allows an attacker to trigger a process abort, especially under constrained memory. This can disrupt SSH services and potentially impact systems relying on SSH for management or communication. This affects `russh-cryptovec` and `russh` packages with versions up to 0.60.2.

## Recommendation

*   Upgrade to Russh version 0.60.3 or later to patch CVE-2026-46673.
*   Monitor process crashes related to `russh` or `russh-cryptovec`, especially in constrained memory environments.
*   Deploy the Sigma rule "Detect Russh CryptoVec Memory Allocation Failure" to identify potential exploitation attempts based on error messages in logs.
*   Consider implementing resource limits for SSH processes to mitigate the impact of potential memory exhaustion attacks.
