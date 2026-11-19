---
brief_id: brief-2026-05-mirasvit-rce
event_id: brief-2026-05-mirasvit-rce
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:3fc64e706e39663cd8038435d33e762b336ae5addd051d58507849b4c0026188
    summary: exploited:true; KEV CVE-2026-45247
    changed_fields:
      - affected_products
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Mirasvit Full Page Cache Warmer for Magento 2 PHP Object Injection RCE (CVE-2026-45247)
slug: 2026-05-mirasvit-rce
description: Mirasvit Full Page Cache Warmer for Magento 2 before version 1.11.12 contains a PHP object injection vulnerability (CVE-2026-45247) that allows unauthenticated attackers to achieve remote code execution by supplying a crafted serialized PHP object in the CacheWarmer cookie.
date: "2026-05-26T15:20:42Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-06-03T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:mirasvit:full_page_cache_warmer:*:*:*:*:*:magento:*:*
tags:
  - php-object-injection
  - rce
  - magento
  - web-application
  - cve-2026-45247
vendors:
  - Magento
  - Mirasvit
products:
  - Full Page Cache Warmer
  - Full Page Cache Warmer for Magento 2
  - Magento
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1212
    technique_name: Exploitation for Credential Access
cves:
  - id: CVE-2026-45247
    cvss: 9.8
    epss: 0.06149
    kev: true
    kev_status: "true"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45247
  - https://mirasvit.com/package/changelog/?package=mirasvit/module-cache-warmer
  - https://sansec.io/research/mirasvit-cache-warmer-object-injection
  - https://www.vulncheck.com/advisories/mirasvit-cache-warmer-for-magento-php-object-injection
  - https://www.cisa.gov/news-events/alerts/2026/06/03/cisa-adds-one-known-exploited-vulnerability-catalog
rules:
  - title: Detect CVE-2026-45247 Exploitation Attempt via CacheWarmer Cookie
    description: Detects CVE-2026-45247 exploitation — An attempt to exploit the PHP object injection vulnerability in Mirasvit Full Page Cache Warmer by sending a CacheWarmer cookie with a serialized PHP object.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1212
    data_sources:
      - webserver
  - title: Detect Suspicious PHP unserialize() Calls in Web Requests
    description: Detects suspicious calls to the PHP unserialize() function within web requests, which can be indicative of PHP object injection attacks.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1212
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-06-14T10:39:32Z"
    level: L1
    summary: new product
    sources:
      - cisa
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-45247
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

CVE-2026-45247 is a critical vulnerability affecting Mirasvit Full Page Cache Warmer for Magento 2, specifically versions prior to 1.11.12. The vulnerability is a PHP object injection flaw that enables unauthenticated attackers to execute arbitrary code remotely. This is achieved by injecting a malicious, serialized PHP object into the CacheWarmer cookie. The application's unsafe use of the `unserialize()` function, in conjunction with available gadget chains within Magento and its dependencies, allows attackers to execute code on the server. This poses a significant risk to e-commerce sites utilizing the affected versions of the Mirasvit cache warmer.

## Attack Chain

1.  An unauthenticated attacker crafts a serialized PHP object containing a malicious payload.
2.  The attacker injects this serialized PHP object into the `CacheWarmer` cookie within an HTTP request to the Magento 2 server.
3.  The Magento 2 application receives the HTTP request containing the malicious cookie.
4.  The Mirasvit Full Page Cache Warmer extension processes the request and extracts the `CacheWarmer` cookie value.
5.  The application calls the PHP `unserialize()` function on the contents of the `CacheWarmer` cookie.
6.  The `unserialize()` function instantiates objects based on the injected serialized data, triggering a pre-existing "gadget chain" within Magento or its dependencies.
7.  The gadget chain executes arbitrary PHP code specified within the malicious object.
8.  The attacker achieves remote code execution on the Magento 2 server, potentially leading to full system compromise.

## Impact

Successful exploitation of CVE-2026-45247 allows an unauthenticated attacker to achieve remote code execution on the Magento 2 server. This can result in complete compromise of the e-commerce platform, including theft of sensitive customer data (e.g., credit card information, personal details), modification of website content, deployment of malicious code, and denial-of-service attacks. Given the severity of the vulnerability and ease of exploitation, all e-commerce businesses using the affected Mirasvit extension are at high risk.

## Recommendation

*   Upgrade Mirasvit Full Page Cache Warmer for Magento 2 to version 1.11.12 or later to patch CVE-2026-45247 (reference: Mirasvit changelog in the References section).
*   Deploy the Sigma rule "Detect CVE-2026-45247 Exploitation Attempt via CacheWarmer Cookie" to detect attempts to exploit this vulnerability (reference: rule below).
*   Implement input validation and sanitization for cookie values to prevent object injection attacks.
*   Consider disabling the Mirasvit Full Page Cache Warmer extension temporarily if an immediate upgrade is not possible.
