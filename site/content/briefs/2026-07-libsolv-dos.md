---
title: 'CVE-2026-48863: libsolv Stack-Based Buffer Overflow Leading to Denial of Service'
slug: 2026-07-libsolv-dos
description: A critical stack-based buffer overflow vulnerability, CVE-2026-48863, has been identified in the PGP verification component of libsolv, allowing a remote attacker to trigger a denial of service by crafting a malicious Ed25519 PGP signature with mismatched MPI lengths, impacting automated package or repository processing workflows.
date: "2026-07-16T01:19:34Z"
lastmod: "2026-07-17T07:04:53Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - vulnerability
  - denial-of-service
  - buffer-overflow
  - linux
  - libsolv
vendors:
  - OpenSUSE
  - Libsolv
products:
  - libsolv (<= 0.7.37)
  - libsolv
affected_os:
  - Linux
cves:
  - id: CVE-2026-48863
    cvss: 7.5
    epss: 0.00801
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48863
  - https://access.redhat.com/security/cve/CVE-2026-48863
  - https://bugzilla.redhat.com/show_bug.cgi?id=2460975
  - https://github.com/openSUSE/libsolv/commit/44f8c085045b1f771641091bbb2b810d12cff9e8#diff-309f245ec9b669ec78b8159c39e6f50130b4d4a0448f742685f7833d04bc4caaR592
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-48863
updates:
  - at: "2026-07-17T07:04:53Z"
    level: L1
    summary: new product
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-48863
---

A significant flaw, identified as CVE-2026-48863, has been discovered in `libsolv`, a core library used in package management for Linux distributions. This vulnerability manifests as a stack-based buffer overflow within the PGP verification component. Specifically, it stems from incorrect length handling when copying the EdDSA 's' Multi-Precision Integer (MPI) into a stack buffer. A remote attacker can exploit this by crafting a specially malformed Ed25519 PGP signature that includes mismatched MPI lengths. When an affected system processes this malicious signature, particularly within automated package or repository processing workflows, the buffer overflow can lead to a denial of service. The impact of this vulnerability is a disruption to critical system functions reliant on `libsolv` for package integrity checks, potentially affecting software updates and deployments.

## Attack Chain

1. A remote attacker crafts a malicious Ed25519 PGP signature designed to exploit the `libsolv` vulnerability.
2. The crafted signature is engineered to contain deliberately mismatched lengths for the EdDSA 's' MPI component.
3. The attacker introduces this malicious PGP signature into an environment where it will be processed by a system utilizing `libsolv` for PGP verification. This could be a compromised package repository, a malicious package, or other distribution channels.
4. An automated package or repository processing workflow, typically performing integrity checks, attempts to verify the supplied signature using the `libsolv` PGP verification component.
5. During the internal signature verification, `libsolv` attempts to copy the malformed EdDSA 's' MPI data into a fixed-size stack buffer.
6. Due to the incorrect length handling and the attacker-controlled mismatched lengths, the copy operation writes beyond the boundaries of the allocated stack buffer, causing a stack-based buffer overflow.
7. This buffer overflow corrupts adjacent memory regions on the stack, leading to a crash or severe instability in the `libsolv` process.
8. The resulting process termination or system instability causes a denial of service, disrupting automated package management and repository processing functionalities.

## Impact

The successful exploitation of CVE-2026-48863 leads directly to a denial of service within automated package or repository processing workflows. This impact can result in significant operational disruption, preventing systems from receiving essential software updates, security patches, or new package installations. For organizations relying on `libsolv` for package management, this vulnerability could halt critical deployment pipelines, compromise the integrity of software distribution, and potentially leave systems unpatched or vulnerable to other threats due to update failures. Given `libsolv`'s role in many Linux distributions, the potential for widespread disruption is considerable.

## Recommendation

* Patch CVE-2026-48863 immediately by updating `libsolv` to version 0.7.38 or later on all affected OpenSUSE systems.
* Monitor system logs for unexpected crashes or service interruptions related to package management daemons or processes that utilize `libsolv`.
