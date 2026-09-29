---
title: adm-zip Decompression Bomb Protection Bypass
slug: 2026-09-adm-zip-bypass
description: The adm-zip Node.js library fails to enforce memory limits during decompression when the ZIP entry uncompressed size header is set to zero, enabling potential memory exhaustion attacks.
date: "2026-09-29T22:18:15Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:adm-zip_project:adm-zip:*:*:*:*:*:node.js:*:*
tags:
  - library
  - vulnerability
  - denial-of-service
vendors:
  - adm-zip
products:
  - adm-zip (<= 0.6.0)
cves:
  - id: CVE-2026-39244
    cvss: 7.5
    epss: 0.00841
references:
  - https://github.com/advisories/GHSA-rcw4-f5rp-g42v
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39244
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade adm-zip to 0.5.18 or later
      owner: IT Operations
      due: 48h
      evidence: Source recommends patch to fix CVE-2026-39244 bypass
  mitigation_plan:
    - priority: immediate
      action: Validate uncompressed size and compression ratios independently before passing data to adm-zip functions.
      owner: Development
      addresses: CVE-2026-39244
      evidence: Source identifies lack of unconditional output capping as the primary bypass vector
---

The adm-zip library for Node.js (version 0.6.0 and earlier) contains a security flaw in its decompression-bomb protection mechanism, which was intended to mitigate CVE-2026-39244. The vulnerability exists within `methods/inflater.js`, where a conditional check applies a `maxOutputLength` constraint to `zlib.inflateRawSync` only if the declared uncompressed size of the ZIP entry is greater than zero.

An attacker can bypass this protection by crafting a malicious ZIP archive where the declared uncompressed size field in the local file header and central directory is set to exactly 0. Because the condition `expectedLength > 0` fails, the `maxOutputLength` option is omitted, causing the library to default to zlib's internal limits rather than the intended application-level cap. This allows a small, highly compressed payload to expand into a significantly larger buffer in memory, leading to potential denial-of-service via OOM (Out-of-Memory) conditions.

## Attack Chain

1. Attacker generates a highly redundant file to achieve high compression ratios (e.g., repeating bytes).
2. Attacker compresses this file using the DEFLATE algorithm.
3. Attacker modifies the ZIP archive structure to set both the local file header and central directory 'uncompressed size' fields to 0.
4. Attacker delivers the malicious ZIP archive to a target application using adm-zip.
5. The target application passes the untrusted ZIP to `new AdmZip(buffer)`.
6. The application calls `.getData()`, `.readFile()`, or similar extraction methods on the malicious entry.
7. The adm-zip library ignores the `maxOutputLength` constraint due to the 0-value size field.
8. Zlib decompresses the full payload into memory, resulting in excessive resource consumption and potential process termination.

## Impact

The vulnerability affects any application using adm-zip to process untrusted archives, such as web upload handlers, CI/CD artifact extractors, or email gateway scanners. Successful exploitation can lead to process crashes and denial-of-service by consuming disproportionate amounts of server memory, bypassing the intended safety guards implemented against decompression bombs.

## Recommendation

- Upgrade the `adm-zip` package to a version that implements unconditional `maxOutputLength` enforcement or adds an independent compression-ratio verification mechanism.
- Until an upgrade is available, implement a wrapper around `adm-zip` functions that validates the actual size of the output buffer against a strict absolute ceiling before returning it to the application logic.
- Monitor logs for unusual memory spikes or process crashes associated with ZIP processing modules.
