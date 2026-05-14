---
title: Svelte devalue Denial-of-Service via Sparse Array Deserialization (CVE-2026-42570)
slug: 2026-05-devalue-dos
description: The `devalue` package is vulnerable to a denial-of-service (DoS) attack (CVE-2026-42570) due to excessive memory allocation during sparse array deserialization via `devalue.parse`, affecting versions 5.6.3 through 5.8.0.
date: "2026-05-14T20:27:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - cve-2026-42570
vendors:
  - npm
products:
  - devalue
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-77vg-94rm-hx3p
  - https://github.com/sveltejs/devalue/releases/tag/v5.8.1
  - CVE-2026-42570
rules:
  - title: Detect Suspicious devalue.parse Usage
    description: Detects suspicious usage of devalue.parse, potentially indicating a denial-of-service attempt.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Excessive Memory Allocation by Node.js
    description: Detects a Node.js process rapidly allocating a large amount of memory, which might be caused by a DoS.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `devalue` package, versions 5.6.3 through 5.8.0, is susceptible to a denial-of-service (DoS) vulnerability. The `devalue.parse` function, when processing crafted inputs, can be tricked into allocating significantly more memory than necessary when deserializing sparse arrays. This behavior stems from quirks in certain JavaScript engines and can lead to excessive memory consumption, potentially crashing the application or server. This vulnerability is identified as CVE-2026-42570 and can be exploited remotely without authentication or user interaction. The vulnerability was patched in version 5.8.1.

## Attack Chain

1. An attacker crafts a malicious payload containing a specially designed sparse array.
2. The attacker sends the malicious payload to a server or application that uses the vulnerable `devalue` library.
3. The application calls `devalue.parse` to deserialize the payload.
4. Due to the structure of the sparse array, the JavaScript engine begins allocating large amounts of memory.
5. Memory consumption increases rapidly, potentially exhausting available resources.
6. The application or server becomes unresponsive due to the memory pressure.
7. The application crashes or the server experiences a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition, rendering the affected application or server unavailable. While the precise number of affected systems is unknown, any application utilizing the vulnerable versions of `devalue` is potentially at risk. The high CVSS score reflects the ease of exploitation and the potential for significant impact on availability.

## Recommendation

*   Upgrade the `devalue` package to version 5.8.1 or later to remediate the vulnerability.
*   Monitor application resource consumption (memory, CPU) for unexpected spikes, especially after processing external data.
*   Deploy the Sigma rule `Detect Suspicious devalue.parse Usage` to identify potential exploitation attempts in your environment.
*   Implement rate limiting and input validation to prevent excessive or malformed data from reaching the `devalue.parse` function.
