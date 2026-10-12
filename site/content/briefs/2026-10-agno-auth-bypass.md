---
title: Authentication Bypass in agno-agi agno via security_key Manipulation
slug: 2026-10-agno-auth-bypass
description: The agno-agi agno library is vulnerable to a remote authentication bypass in the get_authentication_dependency function, allowing unauthenticated access via crafted security_key arguments.
date: "2026-10-12T10:08:07Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:agno-agi:agno:*:*:*:*:*:*:*:*
vendors:
  - agno-agi
products:
  - agno (<= 2.7.3 / <= 3.0.6)
cves:
  - id: CVE-2026-108818
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108818
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all instances of agno-agi agno in production
      owner: SOC
      due: 24h
      evidence: Source identified vulnerability in library versions up to 2.7.3/3.0.6
  mitigation_plan:
    - priority: immediate
      action: Apply WAF or API gateway filtering to inspect and validate security_key parameters
      owner: IT Operations
      addresses: CVE-2026-108818
      evidence: Manipulation of security_key leads to missing authentication
  gaps:
    - Lack of official patch
---

A remote authentication bypass vulnerability (CVE-2026-108818) exists in the agno-agi agno library, affecting all versions up to 2.7.3 and 3.0.6. The flaw resides within the get_authentication_dependency function located in auth.py. By manipulating the security_key argument passed to this function, an attacker can circumvent authentication mechanisms, potentially gaining unauthorized access to application resources. The vulnerability is publicly exploitable, and the maintainers have not yet addressed the issue. Organizations utilizing the agno library for authentication dependency management should audit their implementations for potential impact.

## Impact

Successful exploitation allows remote attackers to bypass authentication controls, potentially leading to unauthorized access to protected services or data managed by applications integrating the agno library. Given the public availability of the exploit, the risk of active exploitation is elevated for systems exposing affected endpoints to the internet.

## Recommendation

- Perform an inventory of all internal applications utilizing the agno-agi agno library to determine exposure.
- Implement compensating controls at the application or API gateway level to validate authentication tokens independently of the agno library until a vendor patch is released.
- Monitor application logs for anomalous requests involving the security_key parameter if visible in input validation or logging layers.
- Restrict network access to services utilizing the vulnerable agno function to trusted internal segments where possible.
