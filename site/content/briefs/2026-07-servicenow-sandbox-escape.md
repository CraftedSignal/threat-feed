---
title: ServiceNow Critical Sandbox Escape Vulnerability (CVE-2026-6875)
slug: 2026-07-servicenow-sandbox-escape
description: ServiceNow has released a security advisory addressing CVE-2026-6875, a critical sandbox escape vulnerability affecting multiple product versions including Brazil, Australia, Zurich, and Yokohama, which could allow an attacker to bypass security boundaries and execute arbitrary code with elevated privileges.
date: "2026-07-14T14:38:44Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - vulnerability
  - servicenow
  - cloud
vendors:
  - ServiceNow
products:
  - Brazil (prior to Brazil EA)
  - Brazil (prior to Brazil GA)
  - Australia (prior to Australia Patch 2)
  - Zurich (prior to Zurich Patch 7b)
  - Zurich (prior to Zurich Patch 9)
  - Yokohama (prior to Yokohama Patch 12 Hot Fix 1b)
  - Yokohama (prior to Yokohama Patch 13)
cves:
  - id: CVE-2026-6875
references:
  - https://cyber.gc.ca/en/alerts-advisories/servicenow-security-advisory-av26-693
  - https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB3137947
---

On July 13, 2026, ServiceNow issued a security advisory (AV26-693) detailing a critical sandbox escape vulnerability, identified as CVE-2026-6875, within its AI Platform. This vulnerability affects several versions across multiple product lines, specifically Brazil (prior to EA and GA releases), Australia (prior to Patch 2), Zurich (prior to Patch 7b and Patch 9), and Yokohama (prior to Patch 12 Hot Fix 1b and Patch 13). A sandbox escape allows an attacker to break out of a restricted execution environment, potentially gaining unauthorized access to underlying systems or sensitive data with higher privileges. While the advisory does not specify observed exploitation in the wild, the critical nature of a sandbox escape warrants immediate attention for organizations utilizing these ServiceNow products to prevent potential data compromise, system disruption, or further network infiltration.

## Impact

Successful exploitation of CVE-2026-6875 could allow an attacker to bypass the security restrictions of the ServiceNow AI Platform's sandbox environment. This could lead to unauthorized access to sensitive data, execution of arbitrary code outside the sandbox, or escalation of privileges on the affected ServiceNow instance. While no specific victims or attack campaigns have been detailed in the advisory, any organization using the vulnerable versions of ServiceNow Brazil, Australia, Zurich, or Yokohama platforms is at risk of severe impact, including data breaches, system integrity compromise, and operational disruption if the vulnerability is exploited by a malicious actor.

## Recommendation

* Review the ServiceNow Security Advisory (KB3137947) linked in this brief immediately to understand the specific affected versions and apply the necessary patches for CVE-2026-6875.
* Apply the recommended updates to your ServiceNow Brazil instances (prior to Brazil EA and Brazil GA), Australia instances (prior to Australia Patch 2), Zurich instances (prior to Zurich Patch 7b and Zurich Patch 9), and Yokohama instances (prior to Yokohama Patch 12 Hot Fix 1b and Yokohama Patch 13).
* Ensure that all ServiceNow platforms are kept up-to-date with the latest security patches to mitigate known vulnerabilities.
