---
title: OpenClaw Race Condition Bypasses Authorization via DNS Rebinding Timing Window (CVE-2026-62212)
slug: 2026-07-openclaw-race-condition
description: A race condition exists in OpenClaw versions before 2026.5.28 within the MS Teams safeFetch DNS rebinding check, allowing a lower-trust caller to exploit a timing window between the DNS validation check and its use, potentially bypassing authorization or policy checks if the affected feature is enabled and reachable.
date: "2026-07-17T02:26:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - race-condition
  - dns-rebinding
  - authentication-bypass
  - cve
vendors:
  - OpenClaw
products:
  - OpenClaw (before 2026.5.28)
cves:
  - id: CVE-2026-62212
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62212
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-wxm8-ghhq-q688
  - https://www.vulncheck.com/advisories/openclaw-authentication-bypass-via-safefetch
---

CVE-2026-62212 describes a race condition vulnerability impacting OpenClaw software versions prior to 2026.5.28. Specifically, the flaw exists within the MS Teams `safeFetch` DNS rebinding check. When this affected feature is enabled and configured to be reachable, a low-trust caller or input path can exploit a timing window. This window occurs between the initial DNS validation check and the subsequent use of the validated resource. Successfully exploiting this race condition allows an attacker to bypass authorization or policy checks that would normally require stronger authentication. The practical impact of this vulnerability is dependent on the specific configuration of the OpenClaw instance and whether a low-trust input can reach the vulnerable code path. Defenders should prioritize patching and reviewing configurations related to `safeFetch` and DNS rebinding to mitigate potential unauthorized actions.

## Impact

If successfully exploited, CVE-2026-62212 can lead to a bypass of established authorization or policy checks within an OpenClaw environment where the vulnerable `safeFetch` feature is enabled. An attacker with lower trust could perform actions that should be restricted to higher-privileged users or processes. The specific unauthorized actions possible and the overall severity of the impact are contingent on the specific operator's configuration, including how the `safeFetch` feature is deployed and whether low-trust inputs can reach the affected code path. While no specific victim counts or sectors are detailed, any organization utilizing vulnerable OpenClaw versions in configurations allowing for low-trust input to the `safeFetch` mechanism is at risk of unauthorized access or actions.

## Recommendation

* Immediately update OpenClaw to version 2026.5.28 or later to address CVE-2026-62212.
* Review the configuration of the MS Teams `safeFetch` feature in OpenClaw environments, particularly assessing its reachability by lower-trust callers or configured input paths.
* Ensure that network segmentation and access controls are properly implemented to restrict access to the `safeFetch` DNS rebinding check from untrusted sources.
