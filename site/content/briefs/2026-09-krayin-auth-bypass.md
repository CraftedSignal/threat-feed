---
title: Authorization Bypass in Krayin laravel-crm
slug: 2026-09-krayin-auth-bypass
description: An authorization bypass vulnerability in the Krayin laravel-crm CanInstall middleware allows remote attackers to manipulate the admin-config-setup endpoint to circumvent security controls.
date: "2026-09-28T01:11:18Z"
lastmod: "2026-10-01T14:11:23Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:krayin:laravel-crm:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://www.exploit-db.com/exploits/52687
tags:
  - vulnerability
  - web-application
  - authentication-bypass
vendors:
  - Krayin
products:
  - laravel-crm (<= 2.2.4)
cves:
  - id: CVE-2026-100885
    cvss: 7.3
    epss: 0.00402
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100885
  - https://www.exploit-db.com/exploits/52687
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Krayin laravel-crm to version 2.2.5
      owner: IT Operations
      due: 48h
      evidence: Upgrading to version 2.2.5 mitigates this issue.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /admin/config/setup endpoints via WAF
      owner: SOC
      addresses: CVE-2026-100885
      evidence: The manipulation results in authorization bypass.
updates:
  - at: "2026-10-01T14:11:23Z"
    level: L2
    summary: poc_available
    sources:
      - exploit-db
    source_urls:
      - https://www.exploit-db.com/exploits/52687
---

Krayin laravel-crm versions up to and including 2.2.4 are vulnerable to an authorization bypass flaw located within the CanInstall middleware (packages/Webkul/Installer/src/Http/Middleware/CanInstall.php). This vulnerability resides in the admin-config-setup API endpoint and enables remote, unauthenticated actors to bypass authorization checks. If successfully exploited, an attacker could interact with sensitive installation or configuration functions, potentially leading to a full compromise of the CRM application's setup state. A proof-of-concept exploit is publicly available, increasing the risk of active exploitation. Defenders should prioritize patching, as this vulnerability provides a direct pathway for unauthorized administrative access to the platform.

## Impact

The vulnerability allows remote attackers to bypass security authorization, which may result in unauthorized modification of CRM configurations or the ability to perform administrative installation tasks. This could lead to data exposure, account takeover, or complete loss of control over the affected Krayin laravel-crm instance.

## Recommendation

- Upgrade Krayin laravel-crm to version 2.2.5 or later to resolve the vulnerability addressed by patch 89f2916b6a46ff91bd1999ce38158fa0de8b9490.
- Review web server access logs for anomalous POST or GET requests targeting the /admin/config/setup or related installation endpoints, particularly from unexpected source IP addresses.
- Restrict access to administrative and installation endpoints at the network perimeter (firewall/WAF) to only authorized management subnets until patching is completed.
