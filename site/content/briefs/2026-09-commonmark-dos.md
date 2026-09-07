---
title: Denial of Service Vulnerability in CommonMark AttributesExtension
slug: 2026-09-commonmark-dos
description: CommonMark versions 1.5.0 through 2.09.0 are susceptible to a CPU-exhaustion denial-of-service attack due to inefficient attribute processing within the AttributesExtension.
date: "2026-09-07T13:36:58Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:commonmark:commonmark:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - web-application
products:
  - commonmark (1.5.0-2.09.0)
cves:
  - id: CVE-2026-86428
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86428
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  mitigation_plan:
    - priority: immediate
      action: Upgrade commonmark to version 2.10.0 or later
      owner: IT Operations
      addresses: CVE-2026-86428
      evidence: NVD vulnerability details confirm 2.10.0 as the patched version
---

CommonMark, a library used for parsing Markdown, contains a vulnerability (CVE-2026-86428) in the AttributesExtension component affecting versions 1.5.0 through 2.09.0. The vulnerability stems from an inefficient algorithm used for merging and filtering attributes when processing user-provided Markdown content. Specifically, an attacker can supply a specially crafted Markdown string containing a high volume of distinct attribute names. When the library attempts to process these attributes, the underlying logic performs a quadratic-time operation that consumes excessive CPU resources. This resource exhaustion leads to a denial-of-service state, where the application becomes unresponsive to legitimate requests. Given that Markdown parsing is frequently utilized in web applications to render user-generated content, this vulnerability poses a significant risk to the availability of systems that rely on this library.

## Impact

Successful exploitation of this vulnerability results in CPU exhaustion, which can cause significant latency or a complete service outage for the hosting application. This denial-of-service vector is particularly dangerous for platforms that allow unauthenticated users to submit or render arbitrary Markdown content, as it allows attackers to disrupt service with relatively small, high-impact payloads.

## Recommendation

Prioritize the immediate remediation of affected environments to prevent service disruption caused by resource exhaustion.

- Upgrade the CommonMark library to version 2.10.0 or later immediately to resolve the algorithmic complexity flaw associated with CVE-2026-86428.
- Implement request timeout mechanisms and CPU resource limits on application components that parse Markdown to mitigate the impact of potential DoS attacks.
- Monitor application-level logs for spikes in CPU utilization correlated with Markdown rendering tasks to identify attempted exploitation.
