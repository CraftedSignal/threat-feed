---
title: GPT Researcher Server-Side Request Forgery Vulnerability (CVE-2026-5633)
slug: 2026-04-gpt-researcher-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in assafelovic gpt-researcher up to version 3.4.3, affecting the ws Endpoint component, allowing a remote attacker to manipulate the source_urls argument and potentially access internal resources or conduct further attacks.
date: "2026-04-06T08:16:39Z"
severities:
  - high
tags:
  - ssrf
  - cve-2026-5633
  - gpt-researcher
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5633
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5633
  - https://github.com/assafelovic/gpt-researcher/
  - https://github.com/assafelovic/gpt-researcher/issues/1696
  - https://vuldb.com/vuln/355421
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect GPT Researcher SSRF Attempt via URL Parameter
    description: Detects potential SSRF attempts against GPT Researcher by monitoring for suspicious URL patterns in the source_urls parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect GPT Researcher SSRF Attempt via External URL
    description: Detects potential SSRF attempts against GPT Researcher by monitoring for suspicious URL patterns in the source_urls parameter to external non-standard ports.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-5633, affects assafelovic's gpt-researcher version 3.4.3 and earlier. The vulnerability resides within the ws Endpoint component and is triggered by manipulating the `source_urls` argument. This flaw allows a remote attacker to potentially force the application to make requests to arbitrary internal or external resources. A publicly disclosed exploit exists, increasing the risk of exploitation. The developers were…
