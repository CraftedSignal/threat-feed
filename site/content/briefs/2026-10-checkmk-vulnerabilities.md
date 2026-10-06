---
title: Multiple Vulnerabilities in Checkmk
slug: 2026-10-checkmk-vulnerabilities
description: Checkmk is affected by multiple vulnerabilities, including CVE-2024-23334 through CVE-2024-23338, which may allow unauthenticated or authenticated attackers to perform cross-site scripting, information disclosure, or data manipulation.
date: "2026-10-06T12:43:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:aiohttp:aiohttp:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
  - cpe:2.3:a:mybb:mybb:*:*:*:*:*:*:*:*
  - cpe:2.3:a:jqlang:jq:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - monitoring
vendors:
  - Checkmk
products:
  - Checkmk (<= 1.7.1)
cves:
  - id: CVE-2024-23334
    cvss: 5.9
    epss: 0.76875
  - id: CVE-2024-23338
  - id: CVE-2024-23335
    cvss: 4.7
    epss: 0.00559
  - id: CVE-2024-23336
    cvss: 5
    epss: 0.00457
  - id: CVE-2024-23337
    cvss: 4.3
    epss: 0.00441
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3746
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Update all Checkmk instances to the latest vendor-patched version.
      owner: IT Operations
      addresses: CVE-2024-23334, CVE-2024-23335, CVE-2024-23336, CVE-2024-23337, CVE-2024-23338
      evidence: Source advisory recommends applying security updates.
---

Checkmk has been identified as vulnerable to a series of security flaws categorized as CVE-2024-23334, CVE-2024-23335, CVE-2024-23336, CVE-2024-23337, and CVE-2024-23338. These vulnerabilities affect the core functionality of the Checkmk monitoring platform. Depending on the specific vulnerability, attackers may be able to execute cross-site scripting (XSS) attacks, gain unauthorized access to sensitive system information, or manipulate monitoring data within the application. These flaws pose a significant risk to the integrity and confidentiality of monitoring environments. Defenders should identify all instances of Checkmk across their infrastructure and apply the vendor-supplied security patches to mitigate the risk of exploitation.

## Impact

Successful exploitation of these vulnerabilities can lead to unauthorized data access, the manipulation of monitoring configurations, or the compromise of user sessions through XSS. This could impact the availability and reliability of infrastructure monitoring services and potentially facilitate further attacks if internal data is exposed to unauthorized parties.

## Recommendation

Prioritize the identification of all Checkmk instances in the production environment. Apply vendor-provided security updates immediately to address CVE-2024-23334, CVE-2024-23335, CVE-2024-23336, CVE-2024-23337, and CVE-2024-23338. Review web server access logs for anomalous patterns targeting Checkmk directories, particularly those involving unexpected script injection or unauthorized attempts to access configuration files.
