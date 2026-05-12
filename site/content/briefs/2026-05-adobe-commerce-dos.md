---
title: Adobe Commerce Uncontrolled Resource Consumption Vulnerability (CVE-2026-34650)
slug: 2026-05-adobe-commerce-dos
description: Adobe Commerce versions 2.4.9-beta1, 2.4.8-p4, 2.4.7-p9, 2.4.6-p14, 2.4.5-p16, 2.4.4-p17 and earlier are susceptible to an uncontrolled resource consumption vulnerability (CVE-2026-34650) that allows an unauthenticated attacker to cause a denial-of-service condition by exhausting system resources.
date: "2026-05-12T20:20:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - resource-exhaustion
  - cve
vendors:
  - Adobe
products:
  - Commerce versions 2.4.9-beta1
  - Commerce versions 2.4.8-p4
  - Commerce versions 2.4.7-p9
  - Commerce versions 2.4.6-p14
  - Commerce versions 2.4.5-p16
  - Commerce versions 2.4.4-p17
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-34650
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34650
  - https://helpx.adobe.com/security/products/magento/apsb26-49.html
rules:
  - title: Detect CVE-2026-34650 Exploitation Attempts — High Request Rate to Specific Endpoint
    description: Detects CVE-2026-34650 exploitation attempts by monitoring for unusually high request rates to a specific endpoint in Adobe Commerce. Adjust the threshold to suit the baseline traffic.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-34650 Exploitation Attempts — Large POST Request Size
    description: Detects CVE-2026-34650 exploitation attempts by monitoring for abnormally large POST request sizes, potentially indicating an attempt to exhaust resources.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
rules_count: 2
---

Adobe Commerce versions 2.4.9-beta1, 2.4.8-p4, 2.4.7-p9, 2.4.6-p14, 2.4.5-p16, and 2.4.4-p17 and earlier are affected by an Uncontrolled Resource Consumption vulnerability, identified as CVE-2026-34650. This vulnerability allows an unauthenticated, remote attacker to exhaust system resources, leading to a denial-of-service (DoS) condition. The vulnerability exists due to improper resource management within the application. Successful exploitation can render the e-commerce platform unavailable, impacting business operations and potentially leading to financial losses. Given the widespread use of Adobe Commerce, this vulnerability poses a significant risk to online businesses if left unpatched.

## Attack Chain

1.  The attacker identifies an Adobe Commerce instance running a vulnerable version (2.4.9-beta1, 2.4.8-p4, 2.4.7-p9, 2.4.6-p14, 2.4.5-p16, 2.4.4-p17 or earlier).
2.  The attacker crafts a malicious HTTP request designed to consume excessive server resources.
3.  The attacker sends the malicious request to a publicly accessible endpoint on the Adobe Commerce server.
4.  The Adobe Commerce application processes the malicious request without proper resource limits.
5.  The server's CPU, memory, or disk I/O resources are gradually exhausted.
6.  Legitimate user requests are delayed or fail due to resource starvation.
7.  The Adobe Commerce application becomes unresponsive, resulting in a denial-of-service condition.
8.  The e-commerce platform is unavailable, preventing users from accessing the site and completing transactions.

## Impact

Successful exploitation of CVE-2026-34650 results in a denial-of-service condition, rendering the Adobe Commerce platform unavailable to legitimate users. The impact includes potential revenue loss due to interrupted sales, damage to brand reputation, and customer dissatisfaction. The severity of the impact depends on the duration of the outage and the volume of transactions processed by the affected e-commerce store. This vulnerability affects multiple versions of Adobe Commerce and can potentially impact a wide range of online businesses.

## Recommendation

*   Upgrade Adobe Commerce to a patched version (later than 2.4.9-beta1, 2.4.8-p4, 2.4.7-p9, 2.4.6-p14, 2.4.5-p16, 2.4.4-p17) to remediate the vulnerability.
*   Monitor web server logs for suspicious HTTP requests that may indicate an attempt to exploit CVE-2026-34650.
*   Implement rate limiting and resource quotas on the Adobe Commerce server to mitigate the impact of resource consumption attacks.
