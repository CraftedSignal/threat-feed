---
title: 'CVE-2026-63030: Critical Remote Code Execution Vulnerability in WordPress Core'
slug: 2026-07-wp2shell-rce-wordpress
description: CVE-2026-63030 is a critical unauthenticated remote code execution vulnerability affecting WordPress Core versions 6.9.0 through 6.9.4 and 7.0.0 through 7.0.1, allowing an unauthenticated attacker to execute arbitrary code via the WordPress REST API batch endpoint, potentially leading to complete website compromise.
date: "2026-07-17T22:47:35Z"
lastmod: "2026-07-20T05:22:22Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=1BE287ED-2D37-54AE-B8E7-515C18143FB2&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - rce
  - web-vulnerability
  - cve
vendors:
  - WordPress
products:
  - WordPress Core 6.9.0
  - WordPress Core 6.9.1
  - WordPress Core 6.9.2
  - WordPress Core 6.9.3
  - WordPress Core 6.9.4
  - WordPress Core 7.0.0
  - WordPress Core 7.0.1
  - WordPress (6.8.0 – 6.8.5)
  - WordPress (6.9.0 – 6.9.4)
  - WordPress (7.0.0 – 7.0.1)
  - WordPress (< 6.9.5)
  - WordPress (< 7.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: reportedly allows an unauthenticated attacker to execute code via the WordPress REST API batch endpoint
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allows an unauthenticated attacker to execute code via the WordPress REST API batch endpoint
    confidence_band: high
cves:
  - id: CVE-2026-63030
    cvss: 9.8
    epss: 0.08946
  - id: CVE-2026-60137
    cvss: 5.9
    epss: 0.04026
references:
  - https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core
  - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63030
  - https://wordpress.org/news/2026/07/wordpress-7-0-2-release/
  - https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/
  - https://blog.cloudflare.com/wordpress-vulnerabilities/
  - https://sploitus.com/exploit?id=1BE287ED-2D37-54AE-B8E7-515C18143FB2&utm_source=rss&utm_medium=rss
  - https://www.securityweek.com/wp2shell-wordpress-vulnerabilities-exploited-in-the-wild/
updates:
  - at: "2026-07-19T15:00:33Z"
    level: L2
    summary: poc_available; added CVE-2026-60137
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=1BE287ED-2D37-54AE-B8E7-515C18143FB2&utm_source=rss&utm_medium=rss
  - at: "2026-07-20T05:22:22Z"
    level: L1
    summary: new product
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/wp2shell-wordpress-vulnerabilities-exploited-in-the-wild/
---

On July 17, 2026, a GitHub Security Advisory was published detailing CVE-2026-63030, a critical unauthenticated remote code execution vulnerability in WordPress Core. This flaw affects WordPress versions 6.9.0 through 6.9.4 and 7.0.0 through 7.0.1. The vulnerability allows an unauthenticated attacker to execute arbitrary code by exploiting the WordPress REST API batch endpoint, specifically when a persistent object cache is not in use. This could lead to a complete compromise of the website and its underlying data without requiring any valid account or user interaction. While the vulnerability has a CVSS score of 7.5, its unauthenticated nature and widespread deployment of WordPress elevate its criticality. The issue is fixed in WordPress 6.9.5 and 7.0.2. At the time of publication, no publicly confirmed in-the-wild exploitation has been observed, but given WordPress's open-source nature and the potential for AI analysis, public proof-of-concept exploits are highly anticipated.

## Attack Chain

1. **Reconnaissance**: An attacker identifies public-facing WordPress instances using web scanning tools or open-source intelligence.
2. **Vulnerability Identification**: The attacker determines that the target WordPress instance is running a vulnerable version (6.9.0-6.9.4 or 7.0.0-7.0.1) and that a persistent object cache, which could mitigate the exploit, is not in use.
3. **Payload Crafting**: The attacker crafts a malicious HTTP POST request, embedding arbitrary code within a specially formatted batch request to the WordPress REST API batch endpoint (e.g., `/wp-json/batch/v1`).
4. **Initial Access**: The crafted request is sent to the vulnerable WordPress server, targeting the REST API batch endpoint.
5. **Code Execution**: The WordPress core, due to CVE-2026-63030, improperly processes the batch request, leading to the execution of the attacker's arbitrary code on the server, exploiting the vulnerable code path enabled by the absence of a persistent object cache.
6. **Persistence and Privilege Escalation**: The executed code establishes persistence (e.g., dropping a webshell, creating new administrator accounts, modifying WordPress core files) and may attempt to escalate privileges on the underlying host operating system.
7. **Impact**: The attacker gains full control over the WordPress instance and potentially the server, enabling actions such as data exfiltration, website defacement, or using the compromised server as a platform for further attacks.

## Impact

Successful exploitation of CVE-2026-63030 grants an unauthenticated attacker remote code execution capabilities on the vulnerable WordPress server. This directly leads to the complete compromise of the website, its content, and any associated databases. Given that WordPress is the most widely used content management system globally, a large number of public-facing websites are potentially at risk. The impact extends to potential data breaches, website defacement, server-side resource abuse (e.g., for cryptocurrency mining or hosting malicious content), and further lateral movement within an organization's network if the WordPress server has access to internal systems.

## Recommendation

* Immediately upgrade all affected WordPress installations to version **6.9.5** or **7.0.2** (or 7.1 Beta 2 for the beta branch) to remediate **CVE-2026-63030**.
* Verify that automatic updates for WordPress are active and have successfully applied the necessary patches to all internet-facing instances.
* Review web server access logs for suspicious POST requests to WordPress REST API batch endpoints (e.g., paths containing `/wp-json/batch/v1`) from unknown or unusual IP addresses, especially around the vulnerability disclosure date.
