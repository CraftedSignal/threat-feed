---
title: Adobe Commerce XXE Vulnerability (CVE-2024-34102) Exploit Released
slug: 2026-05-adobe-commerce-xxe
description: A public exploit, named CosmicSting, has been released for CVE-2024-34102, an XML External Entity (XXE) Injection vulnerability in Adobe Commerce allowing for unauthenticated remote file read, SSRF, and potential RCE.
date: "2026-05-25T18:02:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:adobe:commerce:2.4.2:-:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.2:ext-1:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.2:ext-2:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.2:ext-3:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.2:ext-4:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.2:ext-7:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.3:-:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.3:ext-1:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.3:ext-2:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.3:ext-3:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.3:ext-4:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.3:ext-7:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:-:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p1:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p2:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p3:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p4:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p5:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p6:*:*:*:*:*:*
  - cpe:2.3:a:adobe:commerce:2.4.4:p8:*:*:*:*:*:*
tags:
  - cve-2024-34102
  - xxe
  - adobe commerce
  - magento
vendors:
  - Adobe
products:
  - Commerce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2024-34102
    cvss: 9.8
    epss: 0.94171
references:
  - https://sploitus.com/exploit?id=A364DBD6-75C0-5592-99E6-15C90F955355&utm_source=rss&utm_medium=rss
  - https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102
  - https://sansec.io/research/cosmicsting
  - https://github.com/SamJUK/cosmicsting-validator
  - https://github.com/EQSTLab/CVE-2024-34102
  - https://github.com/th3gokul/CVE-2024-34102
  - https://github.com/projectdiscovery/nuclei-templates
  - https://github.com/ambionics/cnext-exploits
  - https://github.com/spacewasp/public_docs
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=A364DBD6-75C0-5592-99E6-15C90F955355&utm_source=rss&utm_medium=rss
ioc_counts:
  url: 1
rules:
  - title: Detect Adobe Commerce XXE via Guest Cart Endpoint
    description: Detects CVE-2024-34102 exploitation — Attempts to exploit XXE vulnerability in Adobe Commerce guest cart endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Adobe Commerce XXE via Billing Address Endpoint
    description: Detects CVE-2024-34102 exploitation — Attempts to exploit XXE vulnerability in Adobe Commerce billing address endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A public exploit, dubbed "CosmicSting", has been published on Sploitus, targeting CVE-2024-34102, an XML External Entity (XXE) Injection vulnerability in Adobe Commerce (Magento). This vulnerability affects versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8, and earlier. The exploit allows unauthenticated attackers to perform remote file reads, Server-Side Request Forgery (SSRF), and potentially achieve Remote Code Execution (RCE). The exploit suite includes attack vectors targeting various REST endpoints and direct path access to sensitive files. The availability of a working exploit increases the risk to unpatched Adobe Commerce systems significantly, as attackers can now easily leverage this vulnerability.

## Attack Chain

1. An attacker sends a crafted HTTP request to one of the vulnerable Adobe Commerce REST endpoints, such as `/rest/V1/guest-carts/{id}/estimate-shipping-methods`.
2. The HTTP request contains a malicious XML payload designed to exploit the XXE vulnerability (CVE-2024-34102).
3. The Adobe Commerce application processes the XML payload without proper sanitization of external entity references.
4. The application attempts to resolve the external entity, leading to either local file read, or SSRF.
5. If the attacker leverages local file read, sensitive files such as `app/etc/env.php` (containing database credentials and encryption keys) or `/etc/passwd` (for user enumeration) are targeted.
6. If the attacker leverages SSRF, they can interact with internal services or external websites on behalf of the server.
7. Successful exploitation allows the attacker to extract sensitive information, potentially leading to further compromise.
8. In some scenarios, the attacker may be able to leverage the XXE vulnerability to achieve Remote Code Execution (RCE) by chaining it with other vulnerabilities or misconfigurations.

## Impact

Successful exploitation of CVE-2024-34102 can lead to sensitive information disclosure, including database credentials, encryption keys, and system user information. The vulnerability can also be leveraged for Server-Side Request Forgery (SSRF), allowing attackers to interact with internal services. In certain scenarios, Remote Code Execution (RCE) may be possible, potentially allowing complete control over the affected Adobe Commerce instance. The impact is high, with a CVSS score of 9.8, and affects multiple versions of Adobe Commerce.

## Recommendation

*   Apply the security patches provided by Adobe to address CVE-2024-34102 on all Adobe Commerce instances.
*   Deploy the Sigma rule `Detect Adobe Commerce XXE via Guest Cart Endpoint` to your SIEM and tune for your environment.
*   Monitor web server logs for suspicious requests to the identified REST endpoints (`/rest/V1/guest-carts/{id}/estimate-shipping-methods`, `/rest/all/V1/guest-carts/{id}/estimate-shipping-methods`, `/rest/V1/guest-carts/{id}/billing-address`, `/rest/V1/orders`, `/rest/V1/order`) to detect potential exploitation attempts.
