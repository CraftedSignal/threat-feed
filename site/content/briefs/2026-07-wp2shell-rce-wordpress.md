---
title: 'WordPress Core: REST API remote code execution chain (CVE-2026-63030)'
slug: 2026-07-wp2shell-rce-wordpress
description: WordPress Core versions 6.9.0 through 6.9.4 and 7.0.0 through 7.0.1 are affected by a REST API batch-route flaw that can combine with a related SQL injection issue to enable unauthenticated remote code execution.
date: "2026-07-17T22:47:35Z"
lastmod: "2026-10-20T09:30:40Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - wordpress
  - rce
  - web-vulnerability
  - cve
vendors:
  - WordPress
products:
  - WordPress Core
  - WordPress Core 6.9.0
  - WordPress Core 6.9.1
  - WordPress Core 6.9.2
  - WordPress Core 6.9.3
  - WordPress Core 6.9.4
  - WordPress Core 7.0.0
  - WordPress Core 7.0.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The affected WordPress REST API is public-facing, and the vendor advisory describes an unauthenticated remote code execution chain.
    confidence_band: high
cves:
  - id: CVE-2026-63030
    cvss: 9.8
    epss: 0.08946
  - id: CVE-2026-60137
    cvss: 5.9
    epss: 0.04026
references:
  - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q
  - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf
  - https://wordpress.org/news/2026/07/wordpress-7-0-2-release/
  - https://blog.cloudflare.com/wordpress-vulnerabilities/
  - https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/
  - https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core
  - https://www.securityweek.com/wp2shell-wordpress-vulnerabilities-exploited-in-the-wild/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63030
---

WordPress disclosed CVE-2026-63030 on July 17, 2026. Its REST API batch-route flaw can combine with the related SQL injection issue CVE-2026-60137 to cause unauthenticated remote code execution. The RCE chain affects WordPress Core 6.9.0 through 6.9.4 and 7.0.0 through 7.0.1. The SQL injection issue also affects WordPress 6.8, but the vendor says the RCE issue does not affect that branch.

## Detection and impact

The exposed REST API batch route is the entry point for the chain. Successful exploitation can compromise the WordPress site and data available to its server process. Review web server and WAF events for attempts against the affected REST API route, and investigate affected installations for signs of compromise.

## Recommendation

* Update affected WordPress 6.9 installations to 6.9.5 or later and affected 7.0 installations to 7.0.2 or later. WordPress 7.1 beta users should install beta 2 or later.
* Confirm automatic security updates completed on internet-facing sites.
* If an update cannot be applied immediately, use the vendor or WAF provider's temporary protections and review associated security events.
