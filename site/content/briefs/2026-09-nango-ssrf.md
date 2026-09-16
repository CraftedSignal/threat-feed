---
title: SSRF Vulnerability in Nango via Configuration Interpolation
slug: 2026-09-nango-ssrf
description: Nango versions through 0.70.4 are vulnerable to Server-Side Request Forgery due to improper validation of user-supplied configuration values in token and proxy URL templates.
date: "2026-09-16T21:57:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nango:nango:*:*:*:*:*:*:*:*
tags:
  - webserver
  - ssrf
  - cloud
vendors:
  - Nango
products:
  - Nango (<= 0.70.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated attackers can supply malicious configuration values to direct server requests at internal addresses or cloud metadata endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-92804
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92804
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Nango to a version beyond 0.70.4 as soon as a patch is available.
      owner: IT Operations
      addresses: CVE-2026-92804
      evidence: Nango through 0.70.4 fails to validate caller-supplied connection configuration values.
    - priority: short_term
      action: Implement egress filtering on the Nango server to block requests to local cloud metadata (e.g., 169.254.169.254) and internal private IP address ranges.
      owner: Security Engineering
      addresses: CVE-2026-92804
      evidence: Authenticated attackers can supply malicious configuration values to direct server requests at internal addresses or cloud metadata endpoints.
---

Nango versions up to and including 0.70.4 contain a Server-Side Request Forgery (SSRF) vulnerability. The issue arises from the application's failure to properly validate caller-supplied connection configuration values before interpolating them into provider token and proxy URL templates. By submitting maliciously crafted configuration inputs, an authenticated attacker can manipulate these templates to force the Nango server to initiate outbound requests to arbitrary destinations. This is particularly critical for cloud-hosted instances, where attackers can direct requests toward internal infrastructure or cloud instance metadata services (e.g., IMDS) to exfiltrate sensitive provider credentials or internal configuration tokens stored within the environment.

## Impact

Successful exploitation allows authenticated attackers to perform unauthorized requests on behalf of the Nango server. In cloud environments, this may lead to the compromise of provider credentials, access to internal APIs, or the exfiltration of sensitive metadata. The scope of impact is limited to the network reachability of the Nango instance itself.

## Recommendation

Prioritize patching the Nango instance to a version greater than 0.70.4 once an update is available. As a temporary mitigation, audit and restrict the ability of authenticated users to modify connection configurations and implement egress network filtering (e.g., via security groups or firewalls) to prevent the Nango server from reaching cloud metadata endpoints or unauthorized internal IP ranges.
