---
title: Memory Exhaustion Vulnerability in Widely Used Python Library
slug: 2026-03-memory-exhaustion-flaw
description: A memory exhaustion vulnerability (CVE-2026-33155) exists in a widely used Python library, affecting services like SageMaker, DataHub, and acryl-datahub due to an incomplete patch for CVE-2025-58367, requiring pinning to version 8.6.2.
date: "2026-03-19T17:46:05Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - memory-exhaustion
  - vulnerability
  - denial-of-service
  - python
  - supply-chain
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.reddit.com/r/netsec/comments/1ry79kw/we_found_a_memory_exhaustion_cve_in_a_library/
  - https://www.periphery.security/blog/cve-2026-33155---40-bytes-to-chaos
rules:
  - title: Detect Suspicious Pickled Data
    description: Detects network traffic containing potentially malicious pickled data, which could be used to exploit memory exhaustion vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - network_connection
      - windows
  - title: Detect Exceeded Memory Quota
    description: Detects when a process exceeds its allocated memory quota, potentially indicating a memory exhaustion attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical memory exhaustion vulnerability, identified as CVE-2026-33155, has been discovered in a widely used Python library downloaded approximately 29 million times per month. This vulnerability poses a significant threat to services that rely on the affected library, including Amazon SageMaker, DataHub, and acryl-datahub. The issue stems from an incomplete patch for a previous vulnerability, CVE-2025-58367, related to restricted unpickling. Organizations that applied the initial patch may…
