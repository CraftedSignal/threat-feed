---
title: urllib Cross-Origin Redirect Credential Leakage
slug: 2026-08-urllib-credential-leak
description: The urllib library fails to sanitize sensitive headers during cross-origin redirects, leading to the automatic exposure of Authorization, Cookie, and Proxy-Authorization headers to unauthorized endpoints.
date: "2026-08-25T18:50:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-theft
  - nodejs
  - supply-chain
vendors:
  - node-modules
products:
  - urllib (>= 3.0.0, <= 4.9.0)
  - urllib (<= 2.44.0)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The issue is that, when following a redirect to a different origin, urllib preserves the caller-supplied request headers verbatim, including credential-bearing headers.
    confidence_band: high
cves:
  - id: CVE-2026-55553
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-hq3h-g68c-hp78
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55553
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: 'Audit application source code for urllib usage with followRedirect: true.'
      owner: Application Security
      due: 48h
      evidence: Source explicitly warns about automatic redirect-following causing leakage.
  mitigation_plan:
    - priority: immediate
      action: Disable followRedirect in urllib or implement header stripping in wrapper.
      owner: IT Operations
      addresses: CVE-2026-55553
      evidence: Source identifies followRedirect as the triggering mechanism.
---

The Node.js library `urllib` contains a vulnerability (CVE-2026-55553) where credential-bearing request headers are preserved verbatim when following HTTP redirects across different origins. While standard HTTP client behavior typically involves stripping sensitive authentication headers when a request is redirected to a different domain, `urllib` v4.9.0 and earlier versions (including the 2.x branch) fail to implement this security control. This allows an attacker who controls a redirect destination, or who can influence the `Location` header of an initial request, to capture sensitive data such as `Authorization` tokens, `Cookie` session strings, and `Proxy-Authorization` credentials. The vulnerability is triggered automatically when `followRedirect` is set to `true`, requiring no user interaction. This poses a significant risk to applications that handle sensitive API requests or user sessions through the affected library.

## Impact

The impact of this vulnerability is the unauthorized exfiltration of sensitive credentials to attacker-controlled infrastructure. By redirecting a legitimate client request to a malicious origin, an attacker can capture authentication tokens, enabling them to potentially impersonate the client or access protected resources on the original target system. This vulnerability affects any Node.js environment utilizing `urllib` for external communication. Given the automated nature of redirect following, services that interface with dynamic or third-party content are at the highest risk of accidental credential exposure.

## Recommendation

* Update `urllib` to a patched version once available that implements header sanitization for cross-origin requests.
* Implement a wrapper or interceptor around `urllib.request` that checks the domain of the `Location` header during a redirect and strips sensitive headers if the origin changes.
* Audit applications using `urllib` to identify code paths where `followRedirect` is enabled and potentially sensitive headers (Authorization, Cookie) are passed in the options object.
* Review network egress logs for unexpected connections from your backend services to unknown or untrusted external domains.
