---
title: Unbounded Memory Allocation in Xerial snappy-java
slug: 2026-10-snappy-java-dos
description: The snappy-java library prior to version 1.1.10.9 contains an unbounded memory allocation vulnerability that allows attackers to trigger a JVM OutOfMemoryError via crafted input.
date: "2026-10-09T15:32:24Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:xerial:snappy-java:*:*:*:*:*:*:*:*
vendors:
  - Xerial
products:
  - snappy-java (< 1.1.10.9)
cves:
  - id: CVE-2026-108106
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108106
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade snappy-java to version 1.1.10.9 or later
      owner: Application Security
      addresses: CVE-2026-108106
      evidence: snappy-java before 1.1.10.9 contains an unbounded memory allocation vulnerability
---

The snappy-java library versions prior to 1.1.10.9 are susceptible to an unbounded memory allocation vulnerability (CVE-2026-108106). This flaw occurs when the library processes compressed input, as it fails to properly validate the uncompressed length declared in the data. An attacker can supply a small amount of specially crafted input to functions such as Snappy.uncompress, uncompressString, SnappyInputStream, or SnappyFramedInputStream. 

When processed, these crafted inputs force the library to attempt memory allocations of up to 2 GB. This behavior leads to an immediate OutOfMemoryError within the Java Virtual Machine (JVM), resulting in a denial-of-service (DoS) condition. Because snappy-java is a core dependency for many high-performance data processing frameworks and database connectors, this vulnerability presents a significant risk to the availability of Java-based services that process untrusted or externally sourced data streams.

## Impact

Successful exploitation results in an immediate denial-of-service condition due to JVM exhaustion. Systems heavily reliant on snappy-java for deserialization or data stream processing across various enterprise sectors are at risk. If exploited against critical infrastructure or high-availability microservices, this can lead to widespread service disruption, requiring manual intervention or process restarts to restore operation.

## Recommendation

Prioritized actions for engineering and security teams:

- Upgrade the snappy-java library to version 1.1.10.9 or later across all applications and dependencies.
- Review software bills of materials (SBOMs) to identify all instances of snappy-java in the environment.
- Apply the patch for CVE-2026-108106 to any internet-facing or ingestion services that process external input through this library.
