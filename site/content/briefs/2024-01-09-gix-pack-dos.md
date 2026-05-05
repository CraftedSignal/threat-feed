---
title: gix-pack Denial-of-Service Vulnerabilities
slug: 2024-01-09-gix-pack-dos
description: Multiple denial-of-service vulnerabilities exist in `gix-pack`; crafted delta data can cause unchecked array indexing, leading to panics, and uncapped attacker-controlled size headers enable out-of-memory process kills, triggered by malicious pack data during clone/fetch operations.
date: "2026-05-05T19:24:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - git
  - gitoxide
  - gix-pack
vendors:
  - rust
products:
  - gix-pack (<= 0.68.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-x494-mj8g-cj27
rules:
  - title: Detect Gix-Pack Uncapped Memory Allocation
    description: Detects potential out-of-memory (OOM) conditions caused by gix-pack attempting to allocate extremely large buffers, which can indicate a denial-of-service attack.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Gix-Pack Panic via Delta Apply
    description: Detects potential denial-of-service conditions caused by gix-pack panicking due to malformed delta data during clone/fetch operations.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `gix-pack` library, a Rust implementation of Git packfile handling, contains multiple denial-of-service (DoS) vulnerabilities. Specifically, unchecked array indexing in delta processing can lead to panics, and uncapped memory allocation based on attacker-controlled size headers allows for out-of-memory (OOM) attacks. These vulnerabilities are triggered when processing malicious pack data during clone or fetch operations.  The affected versions are `gix-pack` <= 0.68.0. This poses a risk to any application built on gitoxide that clones or fetches from an untrusted remote, including the `gix` CLI, applications using the `gix` crate, and CI/CD systems cloning repositories using gitoxide. A crafted pack entry claiming a multi-terabyte size triggers an immediate process kill, which constitutes a single-packet process kill with no recovery.

## Attack Chain

1. An attacker crafts a malicious Git packfile containing either truncated delta data or an entry with an extremely large `decompressed_size`.
2. A user or automated system initiates a `git clone` or `git fetch` operation from a repository controlled by the attacker.
3. The `gix-pack` library attempts to parse the crafted packfile.
4. If the packfile contains truncated delta data, the `apply()` function in `gix-pack/src/data/delta.rs` attempts to access array indices beyond the bounds of the data buffer, leading to a panic. Alternatively, the `parse_header_info()` function in `gix-pack/src/data/entry/decode.rs` can also panic due to unchecked indexing.
5. If the packfile contains an entry with an extremely large `decompressed_size`, the library attempts to allocate a large buffer using `Vec::with_capacity(size as usize)` in `bytes_to_entries.rs` or `Vec::resize()` in `resolve.rs`.
6. The allocation of the excessively large buffer exhausts available memory, triggering an out-of-memory (OOM) condition.
7. The operating system terminates the process to prevent further memory exhaustion.
8. The application using `gix-pack` crashes, resulting in a denial-of-service.

## Impact

Successful exploitation of these vulnerabilities leads to a denial-of-service (DoS) condition. For the panic vulnerability, a small amount of crafted data causes an immediate process abort. For the OOM vulnerability, a single crafted pack entry header causes the process to attempt a multi-terabyte allocation, leading to process termination by the operating system. This can affect various applications and systems, including the `gix` CLI, applications using the `gix` crate, and CI/CD systems, potentially disrupting software development workflows. The OOM vector represents a severe risk, as it is a single-packet process kill with no recovery.

## Recommendation

- Upgrade to a patched version of `gix-pack` when available.
- Implement input validation on packfile data before processing to mitigate the OOM vulnerability. Specifically, implement a configurable maximum object size and validate claimed sizes against it before allocation, as suggested in the advisory.
- Monitor for process crashes or OOM events related to applications using `gix-pack`. Deploy the Sigma rule `Detect Gix-Pack Uncapped Memory Allocation` to identify potential OOM attacks.
- Consider blocking or filtering network traffic from untrusted Git repositories to prevent malicious packfiles from reaching vulnerable systems.
