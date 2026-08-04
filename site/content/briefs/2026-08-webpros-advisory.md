---
title: Security Updates for cPanel and WP Squared
slug: 2026-08-webpros-advisory
description: WebPros has issued a security advisory addressing HTTP request smuggling and database privilege escalation vulnerabilities in cPanel and WP Squared products.
date: "2026-08-04T17:28:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - vulnerability-management
vendors:
  - WebPros
products:
  - WP Squared
  - cPanel
cves:
  - id: CVE-2026-58047
    epss: 0.00445
  - id: CVE-2026-58048
    epss: 0.00503
references:
  - https://cyber.gc.ca/en/alerts-advisories/webpros-security-advisory-av26-772
  - https://support.cpanel.net/hc/en-us/articles/42285024734743-Security-CVE-2026-58047-HTTP-Request-Smuggling
  - https://support.cpanel.net/hc/en-us/articles/42285745783703-Security-CVE-2026-58048-Database-Privilege-Escalation
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch cPanel and WP Squared to the latest versions defined in AV26-772.
      owner: IT Operations
      due: 48h
      evidence: Vendor security advisory AV26-772.
---

WebPros has released a security advisory (AV26-772) addressing multiple vulnerabilities affecting their cPanel and WP Squared product lines. These vulnerabilities include CVE-2026-58047, which relates to HTTP Request Smuggling, and CVE-2026-58048, which involves database privilege escalation. 

The scope of the affected versions is extensive, covering multiple release branches of cPanel (11.110, 11.118, 11.126, 11.134, 11.136, and 138.1) and WP Squared versions prior to 11.138.1.6. These flaws pose significant risks to web hosting environments, as HTTP request smuggling can potentially lead to cache poisoning or bypassing security controls, while the privilege escalation vulnerability could allow an authenticated user to gain unauthorized access to database administrative functions. Administrators are urged to apply the identified patches to maintain the security and integrity of their hosting platforms.

## Impact

Successful exploitation of these vulnerabilities could result in unauthorized administrative access to databases or the manipulation of web server traffic. Given the ubiquitous nature of cPanel in the web hosting industry, these vulnerabilities potentially impact thousands of hosting providers and the underlying websites they manage, leading to data exfiltration or site defacement.

## Recommendation

Prioritized, concrete actions for detection engineering and administrative teams:
- Immediately patch all instances of cPanel and WP Squared to the versions specified in the WebPros security advisory (AV26-772).
- Verify patch levels for all identified affected product versions listed in the vendor advisory.
- Review web server access logs for anomalous HTTP request patterns that deviate from standard traffic profiles, specifically targeting headers associated with HTTP Request Smuggling (e.g., conflicting Content-Length and Transfer-Encoding headers).
