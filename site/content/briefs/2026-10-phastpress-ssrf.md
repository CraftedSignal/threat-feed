---
title: PhastPress Plugin for WordPress SSRF Vulnerability
slug: 2026-10-phastpress-ssrf
description: The PhastPress plugin for WordPress is vulnerable to Server-Side Request Forgery via insecure Host header processing, allowing unauthenticated attackers to bypass URL allowlists and perform unauthorized requests.
date: "2026-10-15T06:35:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:phastpress:phastpress:*:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - ssrf
  - wordpress
products:
  - PhastPress (<= 3.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to spoof the header to match any target URL, bypassing the whitelist and forcing the server to make HTTP requests to arbitrary internal or external destinations.
    confidence_band: high
cves:
  - id: CVE-2026-3712
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3712
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update PhastPress plugin to a version later than 3.10
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in all versions up to and including 3.10
  mitigation_plan:
    - priority: immediate
      action: Update PhastPress plugin to a version later than 3.10
      owner: IT Operations
      addresses: CVE-2026-3712
      evidence: Source states all versions up to 3.10 are vulnerable
---

The PhastPress plugin for WordPress (versions 3.10 and earlier) contains a critical Server-Side Request Forgery (SSRF) vulnerability identified as CVE-2026-3712. The flaw exists within the plugin's scripts service endpoint, which fails to securely validate user input when constructing its URL whitelist. Specifically, the service dynamically pulls values from the 'Host' header provided in incoming HTTP requests. Because this header is attacker-controlled, an unauthenticated actor can spoof the 'Host' header to match legitimate whitelist patterns, effectively bypassing security controls. Once bypassed, the plugin forces the underlying WordPress server to perform HTTP requests to arbitrary destinations, including internal network resources and external services. This can lead to unauthorized data access, network reconnaissance, or potential interaction with sensitive internal APIs that are otherwise inaccessible from the public internet.

## Impact

Successful exploitation allows unauthenticated attackers to force the web server to make arbitrary requests, potentially exposing internal-only services or exfiltrating sensitive content returned by the target endpoints. This represents a significant risk to organizations hosting internal APIs or restricted microservices within the same network as the vulnerable WordPress installation.

## Recommendation

Update the PhastPress plugin to the latest version immediately to remediate CVE-2026-3712. If patching is not immediately feasible, monitor web server logs for suspicious HTTP requests involving the PhastPress scripts service endpoint, particularly those where the Host header does not match expected site traffic patterns.
