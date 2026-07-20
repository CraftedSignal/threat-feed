---
title: node-tar Decompression/Parse DoS Vulnerability via Unlimited Input
slug: 2026-07-node-tar-dos
description: A Denial of Service (DoS) vulnerability (CVE-2026-59873) exists in the `node-tar` library (npm/tar <= 7.5.18) due to a lack of hard upper bounds on total decompressed data or entry counts, allowing an unauthenticated attacker to craft a small 'Gzip Bomb' archive that exhausts server resources like disk space and CPU, leading to system-wide failure and service outages.
date: "2026-07-20T21:56:26Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:isaacs:tar:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - software-supply-chain
  - library-vulnerability
  - nodejs
  - tar
  - gzip-bomb
  - cve-2026-59873
vendors:
  - npm
products:
  - tar <= 7.5.18
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: crash services
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: allows an attacker to exhaust server resources (disk space and CPU)
    confidence_band: high
cves:
  - id: CVE-2026-59873
    cvss: 7.5
    epss: 0.00358
references:
  - https://github.com/advisories/GHSA-23hp-3jrh-7fpw
---

An unauthenticated attacker can exploit a critical Denial of Service (DoS) vulnerability, identified as CVE-2026-59873, in the `node-tar` library (npm/tar versions <= 7.5.18). This vulnerability stems from the library's failure to enforce hard upper bounds on the total volume of decompressed data or the number of entries during archive extraction. Attackers can leverage this by crafting a small, malicious "Gzip Bomb" archive. When processed by a vulnerable application, this archive rapidly expands to consume all available disk space and CPU resources on the target system. This can lead to system-wide failures and widespread service outages for any application that relies on `node-tar` to process archives from untrusted sources, such as npm registries, CI/CD pipelines, or file-sharing platforms.

## Attack Chain

1. An unauthenticated attacker crafts a small, highly compressed archive, commonly referred to as a "Gzip Bomb".
2. This malicious archive includes a TAR header that falsely claims an extremely large file size for its contents (e.g., 10 gigabytes).
3. The actual content of the archive consists of highly compressible data, such as repeating null bytes.
4. A vulnerable application using the `node-tar` library (version 7.5.18 or earlier) attempts to extract this attacker-supplied archive.
5. The `node-tar` `Unpack` stream processes the archive without enforcing any global limits on the total decompressed data size or the number of entries.
6. The library continuously writes the expanded, highly compressible data to the target system's disk, leading to rapid consumption of all available storage space.
7. The target system's disk resources are exhausted, causing critical applications and services to crash, resulting in a complete Denial of Service.

## Impact

This vulnerability poses a critical Denial of Service (DoS) threat. Any application or service that utilizes `node-tar` (npm/tar) to extract archives from untrusted sources is susceptible. This could include crucial infrastructure like npm registries, CI/CD pipelines, or file-sharing platforms. An unauthenticated attacker can, with a minuscule input, trigger the rapid exhaustion of all available disk space and CPU resources on the target system. This leads to system instability, crashes, and widespread service outages, preventing legitimate users from accessing critical services and significantly disrupting operations.

## Recommendation

* Patch CVE-2026-59873 by updating the `npm/tar` package to a version greater than 7.5.18 immediately.
* Implement resource limits, such as disk quotas and process memory limits, on systems that process untrusted archives to mitigate the impact of resource exhaustion attacks.
* Monitor disk space utilization and CPU load on servers processing user-supplied archives to detect and respond to abnormal resource consumption patterns.
