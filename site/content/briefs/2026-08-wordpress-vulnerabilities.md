---
title: Multiple Vulnerabilities in WordPress
slug: 2026-08-wordpress-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-64638, affect WordPress versions prior to 7.0.3, enabling privilege escalation, data breaches, and Server-Side Request Forgery (SSRF).
date: "2026-08-07T21:21:16Z"
lastmod: "2026-08-08T00:59:45Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=742A12A7-2805-526E-80AB-8421D4832885&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - cve
  - web-application
  - patch-management
vendors:
  - WordPress
products:
  - WordPress (< 7.0.3)
  - WordPress Core (< 7.0.3)
cves:
  - id: CVE-2026-64638
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0979/
  - https://wordpress.org/news/2026/08/wordpress-7-0-3-release/
  - https://www.cve.org/CVERecord?id=CVE-2026-64638
  - https://sploitus.com/exploit?id=742A12A7-2805-526E-80AB-8421D4832885&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=742A12A7-2805-526E-80AB-8421D4832885
ioc_counts:
  url: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch all WordPress instances to 7.0.3
      owner: IT Operations
      due: 24h
      evidence: Vendor security bulletin wordpress-7-0-3
  mitigation_plan:
    - priority: immediate
      action: Upgrade WordPress core
      owner: IT Operations
      addresses: CVE-2026-64638
      evidence: CERTFR-2026-AVI-0979
updates:
  - at: "2026-08-08T00:59:45Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=742A12A7-2805-526E-80AB-8421D4832885&utm_source=rss&utm_medium=rss
---

The French National Cybersecurity Agency (ANSSI) has issued an advisory regarding multiple security vulnerabilities discovered in the WordPress content management system. These vulnerabilities affect all versions of WordPress prior to 7.0.3, which was released on August 6, 2026. The identified security flaws introduce significant risks to web server environments, including the potential for remote attackers to execute cross-site scripting (XSS), conduct Server-Side Request Forgery (SSRF), bypass security controls, and perform privilege escalation to gain unauthorized access to administrative functions. Organizations running self-hosted WordPress instances are advised to evaluate their exposure and apply the 7.0.3 patch to mitigate these vulnerabilities. Given the ubiquity of the WordPress platform, successful exploitation could facilitate widespread data exfiltration and server compromise.

## Impact

Successful exploitation of these vulnerabilities could result in full administrative account takeover, unauthorized access to sensitive database content, and the ability to leverage the compromised server as a pivot point for internal network scanning or attacks against backend infrastructure via SSRF.

## Recommendation

- Upgrade all WordPress instances to version 7.0.3 or later immediately to address CVE-2026-64638.
- Review web server access logs for anomalous requests to administrative endpoints, particularly those originating from unexpected IP addresses or containing suspicious URI patterns associated with SSRF or XSS.
- Implement a Web Application Firewall (WAF) to filter common web exploitation patterns targeting CMS vulnerabilities.
