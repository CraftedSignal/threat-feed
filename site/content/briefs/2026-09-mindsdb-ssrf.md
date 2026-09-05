---
title: Unauthenticated SSRF Vulnerability in MindsDB Crawler
slug: 2026-09-mindsdb-ssrf
description: MindsDB versions 26.1.0 and earlier are vulnerable to unauthenticated server-side request forgery (SSRF) in the web crawler handler, enabling unauthorized access to internal resources and cloud metadata.
date: "2026-09-05T11:32:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mindsdb:mindsdb:*:*:*:*:*:*:*:*
tags:
  - web-application
  - ssrf
  - vulnerability
vendors:
  - MindsDB
products:
  - MindsDB (<= 26.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: MindsDB through 26.1.0 contains a server-side request forgery vulnerability in the web crawler handler that allows unauthenticated attackers to fetch arbitrary URLs
    confidence_band: high
cves:
  - id: CVE-2026-86173
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86173
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade MindsDB to a version released after 26.1.0
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-86173 vulnerability affects versions up to 26.1.0
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound access from MindsDB server to 169.254.169.254 and internal subnets
      owner: Network Security
      addresses: CVE-2026-86173
      evidence: Source states SSRF allows access to internal services and cloud metadata
---

MindsDB versions up to and including 26.1.0 contain a Server-Side Request Forgery (SSRF) vulnerability within the web crawler handler. The flaw exists in the 'CrawlerTable.list' function, which fails to properly validate user-supplied URLs. Due to a default empty configuration for the allowlist, an unauthenticated attacker can supply arbitrary target URLs to the crawler. This allows the application to be coerced into making outbound requests on behalf of the server. The vulnerability is significant as it provides a mechanism to bypass network perimeters, potentially leading to unauthorized interaction with internal services or the exfiltration of sensitive cloud instance metadata. Defenders should treat this as a high-priority risk if the MindsDB instance is deployed within a cloud environment or has access to internal network segments.

## Impact

Successful exploitation allows attackers to perform reconnaissance on internal networks, access hidden services, or retrieve sensitive configuration and authentication data from cloud metadata services. This could facilitate lateral movement or further exploitation of infrastructure components within the target organization.

## Recommendation

- Upgrade MindsDB to a version beyond 26.1.0 as soon as a patch is available.
- Implement restrictive network egress policies for the MindsDB application host to prevent access to internal RFC1918 address space and cloud metadata IP addresses (e.g., 169.254.169.254).
- Configure the MindsDB crawler allowlist explicitly, rather than relying on default settings, to restrict permissible target domains.
