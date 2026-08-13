---
title: Flyto2 Core SSRF Vulnerability (CVE-2026-73530)
slug: 2026-08-flyto2-ssrf
description: Flyto2 Core versions prior to 2.28.0 are susceptible to SSRF via an IPv6 loopback bypass in the is_private_ip() function, enabling access to internal services.
date: "2026-08-13T22:08:06Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Flyto2
products:
  - Flyto2 Core
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Flyto2 Core before 2.28.0 contains a server-side request forgery guard bypass vulnerability that allows attackers to reach internal services.
    confidence_band: high
cves:
  - id: CVE-2026-73530
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73530
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Flyto2 Core to version 2.28.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-73530 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Egress filtering for internal loopback addresses
      owner: IT Operations
      addresses: CVE-2026-73530
      evidence: NVD vulnerability details
---

Flyto2 Core before version 2.28.0 contains a Server-Side Request Forgery (SSRF) vulnerability that allows unauthorized access to internal network services. The vulnerability originates in the is_private_ip() function, which fails to correctly sanitize or block the IPv6 loopback address notation `::`. Because the kernel interprets `::` identically to `0.0.0.0` (loopback), attackers can circumvent existing private IP range filters and hostname validation checks. This flaw affects multiple modules, specifically `http.get`, `http.request`, and `http.batch`. By manipulating these functions to target `::`, an attacker can force the application to make HTTP requests to internal services bound to the IPv6 loopback interface, potentially leading to unauthorized data exfiltration or service interaction. Organizations running Flyto2 Core must prioritize upgrading to version 2.28.0 or later.

## Impact

Successful exploitation allows remote, unauthenticated attackers to interact with internal services that are otherwise protected by IP filtering or hostname validation, potentially leading to the leakage of internal application states, configuration data, or other sensitive information reachable via the loopback interface.

## Recommendation

- Upgrade all instances of Flyto2 Core to version 2.28.0 or later immediately to patch the is_private_ip() filter logic.
- Review web application logs for HTTP request patterns utilizing `::` or IPv6 loopback notations within URL parameters handled by the `http` modules.
- Implement outbound network egress filtering at the host level to prevent the web application process from making unnecessary requests to local loopback addresses if not required by business logic.
