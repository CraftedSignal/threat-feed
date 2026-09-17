---
title: ExifReader Denial of Service via Crafted HEIC/AVIF Files
slug: 2026-09-exifreader-dos
description: ExifReader version 4.41.0 is susceptible to a heap exhaustion denial-of-service vulnerability due to an unbounded object allocation loop when parsing malicious ISO-BMFF iloc box structures.
date: "2026-09-17T19:14:14Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:exifreader_project:exifreader:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - vulnerability
  - memory-exhaustion
vendors:
  - exifreader
products:
  - exifreader (<= 4.41.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A 6KB file exhausts all system memory and crashes the Node.js process with a JavaScript heap out-of-memory error.
    confidence_band: high
cves:
  - id: CVE-2026-85715
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-pj96-35fp-cfcc
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-85715
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Audit applications utilizing ExifReader to identify exposed image processing endpoints
      owner: Application Security
      due: 24h
      evidence: Source document identifies this as a DoS risk for applications processing user uploads.
  mitigation_plan:
    - priority: immediate
      action: Patch exifreader to 4.41.1 or later
      owner: Application Security
      addresses: CVE-2026-85715
      evidence: Suggested fix in source advisory.
---

ExifReader 4.41.0 contains a vulnerability in its ISO-BMFF container parsing logic that can be leveraged to cause a denial-of-service (DoS) condition. The vulnerability resides within the `getItems()` function of `src/image-header-iso-bmff-iloc.js`. Specifically, when parsing the `iloc` (Item Location) box of HEIC or AVIF image files, the library reads configuration fields (`offsetSize`, `lengthSize`, `baseOffsetSize`, and `indexSize`) which control how the parser iterates through data extents. 

When an attacker provides a crafted file where these size fields are set to zero, the library's extent-parsing loop fails to advance the buffer offset while simultaneously pushing new objects onto the `item.extents` array for every iteration defined by the `itemCount` and `extentCount` headers. This leads to unbounded memory consumption. A malicious file as small as 652 bytes can trigger 400MB of heap growth, while files in the kilobyte range result in an out-of-memory (OOM) crash, effectively terminating the Node.js process. This poses a significant risk to any service or application utilizing this library for processing user-provided imagery.

## Attack Chain

1. Attacker crafts a malicious HEIC/AVIF file container following the ISO-BMFF specification.
2. The `iloc` box is populated with an `itemCount` and `extentCount` set to the maximum allowed values (up to 65535 each).
3. The `offsetSize`, `lengthSize`, and `baseOffsetSize` fields in the `iloc` header are set to zero, signaling that these values are absent in the byte stream.
4. The victim application receives the malicious image and passes the buffer to `ExifReader.load()`.
5. The library's `getItems()` function initiates a nested loop, iterating based on the attacker-controlled `itemCount` and `extentCount`.
6. Within the loop, the parser performs unconditional object allocations for each extent without advancing the buffer offset.
7. The heap usage of the Node.js process expands rapidly until it reaches the memory limit defined by the environment.
8. The process crashes with a JavaScript heap out-of-memory error, resulting in a successful denial-of-service against the host application.

## Impact

Successful exploitation results in an immediate denial-of-service for the application process. This vulnerability affects any service (such as web servers, backend media processors, or mobile app backends) that accepts and processes HEIC or AVIF images using ExifReader 4.41.0. Given that a crash-inducing payload is less than 2KB, this is highly effective against internet-facing services, potentially causing significant downtime or resource contention across shared infrastructure.

## Recommendation

1. Upgrade to a patched version of ExifReader once available.
2. Implement a per-item or global extent allocation limit in `src/image-header-iso-bmff-iloc.js` to bound the memory growth.
3. Apply an input validation gate to skip the extent parsing loop if `offsetSize`, `lengthSize`, and `baseOffsetSize` are all zero, as per the suggested fix in the advisory.
4. Implement memory resource monitoring and limits for Node.js worker processes that handle image parsing to mitigate potential OOM crashes.
