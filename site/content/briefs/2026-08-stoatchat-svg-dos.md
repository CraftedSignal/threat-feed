---
title: Denial of Service via SVG ViewBox Exploitation in stoatchat
slug: 2026-08-stoatchat-svg-dos
description: stoatchat versions prior to 0.15.0 contain an uncontrolled resource consumption vulnerability in its proxy endpoint that allows unauthenticated attackers to cause memory exhaustion through malicious SVG files.
date: "2026-08-16T14:25:52Z"
lastmod: "2026-08-17T12:48:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - cve
  - vulnerability
  - authorization-bypass
  - cve-2026-74869
  - privacy
vendors:
  - stoatchat
products:
  - stoatchat
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can host malicious SVGs with extremely large width and height values and trigger concurrent requests to exhaust available memory across proxy replicas.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can subscribe to any server's member-update topic by sending a Subscribe message with an arbitrary server ID, receiving live UserUpdate events including display names, avatars, and status changes for members they should not have access to.
    confidence_band: high
cves:
  - id: CVE-2026-73057
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73057
  - https://github.com/stoatchat/stoatchat/security/advisories/GHSA-x87r-h3mq-7mgr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74869
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade stoatchat to version 0.15.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-73057 advisory
  mitigation_plan:
    - priority: immediate
      action: Configure WAF/Gateway to block/limit large SVG uploads to the proxy endpoint
      owner: IT Operations
      addresses: CVE-2026-73057
      evidence: Source support
updates:
  - at: "2026-08-17T12:48:24Z"
    level: L2
    summary: added coverage for stoatchat
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74869
---

The stoatchat application contains a security vulnerability (CVE-2026-73057) affecting versions prior to 0.15.0, where the proxy endpoint fails to properly validate the 'viewBox' dimensions of user-supplied SVG images. This flaw, classified under CWE-400 (Uncontrolled Resource Consumption), allows remote, unauthenticated attackers to trigger significant memory consumption by submitting SVGs with excessively large width and height values. By sending multiple concurrent requests containing these malformed image payloads to the proxy, an attacker can exhaust system memory across proxy replicas, leading to a Denial of Service (DoS) condition. This issue is particularly critical for deployments utilizing the proxy feature, as it can disrupt the availability of the entire service by forcing the underlying process to allocate excessive memory for image rendering.

## Impact

Successful exploitation of this vulnerability leads to service-wide Denial of Service by exhausting host or container memory. This can impact all users of the stoatchat instance, causing instability and potential crashes of proxy replicas. Given the lack of authentication required to hit the proxy endpoint, the barrier to entry for an attacker is minimal.

## Recommendation

1. Upgrade all instances of stoatchat to version 0.15.0 or later to apply the necessary input validation for SVG rendering.
2. Implement request rate limiting and payload size restrictions on the proxy endpoint to mitigate the impact of volumetric or resource-intensive requests.
3. Monitor host-level memory usage metrics for application processes; a spike in resident set size (RSS) immediately following requests to the proxy endpoint may indicate exploitation attempts.
