---
title: Renovate Allowlist Bypass via Shared Presets
slug: 2026-10-renovate-allowlist-bypass
description: Renovate versions prior to 44.60.1 are vulnerable to an allowlist bypass that permits repository users to inject arbitrary HTTP headers via malicious shared presets.
date: "2026-10-15T00:34:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:renovate:renovate:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - supply-chain
  - renovate
  - cve-2026-110865
vendors:
  - Renovate
products:
  - Renovate (< 44.60.1)
cves:
  - id: CVE-2026-110865
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110865
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Renovate instances to 44.60.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source states Renovate before 44.60.1 contains the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Renovate to 44.60.1
      owner: IT Operations
      addresses: CVE-2026-110865
      evidence: NVD vulnerability disclosure
---

Renovate before version 44.60.1 contains a vulnerability that allows repository users to evade 'allowedHeaders' restrictions. By leveraging the way Renovate handles shared presets, an attacker can supply internal or externally sourced presets containing unvalidated 'hostRules[].headers'. When processed, these presets allow the injection of custom HTTP headers into requests that the Renovate application sends to external hosts. This vulnerability is significant as it permits the redirection of sensitive authentication tokens or credentials to attacker-controlled infrastructure, or the manipulation of requests to downstream services, potentially leading to unauthorized data exposure. Organizations utilizing Renovate for dependency management should prioritize upgrading to version 44.60.1 or later to mitigate this risk.

## Impact

Successful exploitation allows repository users to bypass security controls by injecting arbitrary headers into outbound requests made by the Renovate service. This can lead to unauthorized data exposure, potential credential theft via header manipulation, and the ability to influence requests directed at third-party hosts within the supply chain infrastructure.

## Recommendation

* Upgrade all instances of Renovate to version 44.60.1 or later immediately.
* Audit existing shared presets for the presence of unauthorized or suspicious 'hostRules' blocks, specifically inspecting the 'headers' property for non-standard or external destination domains.
* Implement stricter egress filtering for the Renovate service to prevent connections to unauthorized external hosts if header injection is attempted.
