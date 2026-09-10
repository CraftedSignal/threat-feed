---
title: Domain-Restriction Bypass in n8n OpenAI Chat Model Node
slug: 2026-09-n8n-domain-bypass
description: An unauthenticated credential access vulnerability in n8n allows users to bypass domain restrictions in the OpenAI Chat Model node via the model-search endpoint, leading to unauthorized credential exposure.
date: "2026-09-10T18:53:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:n8n:n8n:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - webserver
  - credential-theft
  - n8n
  - cve-2026-86082
vendors:
  - n8n GmbH
products:
  - n8n (< 1.123.76, >= 2.0.0 < 2.37.7, >= 2.38.0 < 2.38.2)
cves:
  - id: CVE-2026-86082
    epss: 0.00246
references:
  - https://github.com/advisories/GHSA-34ff-336r-5q23
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86082
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade n8n to 1.123.76, 2.37.7, 2.38.2 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrade to remediate CVE-2026-86082
  mitigation_plan:
    - priority: immediate
      action: Rotate OpenAI API keys and review account logs
      owner: Security Operations
      addresses: CVE-2026-86082
      evidence: Source recommends credential rotation for exposed keys
---

A security vulnerability in n8n (CVE-2026-86082) allows authenticated users to bypass configured domain restrictions within the OpenAI Chat Model node. While the primary OpenAI request path correctly validated custom base URLs against allowed-domain configurations, the secondary model-search dropdown endpoint failed to perform this check. An attacker able to manipulate request options could define a custom base URL that directed sensitive requests to an arbitrary, attacker-controlled host while still including the original, valid OpenAI credentials. This flaw enables the exfiltration of API keys or the use of credentials against unauthorized third-party infrastructure. This vulnerability affects multiple versions of n8n across the 1.x and 2.x branches and necessitates a prompt upgrade to the patched versions to ensure consistent credential protection across all API call sites.

## Impact

The vulnerability allows unauthorized use of OpenAI credentials by routing requests to external hosts, potentially leading to credential exposure or unauthorized usage of services. If compromised, an attacker can leverage these credentials to make unauthorized API calls. Security teams should assume any n8n instance with domain-restricted OpenAI credentials might have been subject to credential exposure if the instance was accessible to untrusted users prior to patching.

## Recommendation

- Upgrade n8n to version 1.123.76, 2.37.7, 2.38.2, or later to implement centralized domain validation for all OpenAI call sites.
- Rotate all OpenAI API keys currently stored in n8n instances if there is suspicion of unauthorized access or exposure via this vector.
- Review OpenAI account usage logs for any traffic originating from unexpected or unauthorized endpoints.
- Restrict access to the n8n instance to trusted users until the software is patched.
