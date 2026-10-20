---
brief_id: brief-2026-10-20-apache-tomcat-buffer-under-read
event_id: brief-2026-10-20-apache-tomcat-buffer-under-read
revision: 1
activity_at: "2026-10-20T16:36:15Z"
title: 'Apache Tomcat: Buffer under-read vulnerability (CVE-2026-103119)'
slug: 2026-10-apache-tomcat-buffer-under-read
description: A buffer under-read vulnerability in Apache Tomcat versions 11.0.0-M25 through 11.0.26 allows for sensitive data leakage or request failure by incorrectly mixing response bodies between consecutive requests on the same connection.
date: "2026-10-20T16:36:15Z"
lastmod: "2026-10-20T19:45:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; no TTPs or IOCs were provided by the source, so they have been omitted.
cpes:
  - cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*
tags:
  - web-application
  - vulnerability
  - http2
vendors:
  - Apache
products:
  - Tomcat (11.0.0-M25 through 11.0.26)
  - Tomcat (11.0.22-11.0.26)
  - Tomcat (10.1.55-10.1.60)
  - Tomcat (9.0.118-9.0.122)
cves:
  - id: CVE-2026-103119
    cvss: 9.1
    kev_status: "false"
  - id: CVE-2026-101356
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103119
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101356
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Apache Tomcat to version 11.0.27
      owner: IT Operations
      due: 48h
      evidence: Users are recommended to upgrade to version 11.0.27, which fixes the issue.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Tomcat to 11.0.27
      owner: IT Operations
      addresses: CVE-2026-103119
      evidence: Users are recommended to upgrade to version 11.0.27, which fixes the issue.
updates:
  - at: "2026-10-20T19:45:18Z"
    level: L2
    summary: added coverage for Tomcat (11.0.22-11.0.26) +2 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101356
---

Apache Tomcat versions 11.0.0-M25 through 11.0.26 contain a buffer under-read vulnerability identified as CVE-2026-103119. This flaw is triggered during large non-blocking write operations. When an application performs a large write, the internal buffer management logic can fail, causing the response body to be incorrectly segmented. Consequently, a portion of the response body from a current request may be unintentionally appended to the subsequent request handled over the same persistent HTTP connection. This behavior can lead to denial-of-service conditions through request failures or, more critically, the unauthorized disclosure of response data to the user of the following request. Given the potential for cross-user data leakage, organizations utilizing these versions of Apache Tomcat in multi-tenant or sensitive environments should prioritize remediation.

## Impact

Successful exploitation can lead to a loss of data confidentiality, where sensitive information from one user's request is leaked to the subsequent request on the same connection. Furthermore, the mismatch in expected data streams often results in request processing failures, which can be leveraged to cause service instability.

## Recommendation

- Upgrade all instances of Apache Tomcat to version 11.0.27 or later to address the root cause of the buffer under-read.
- Review web server access logs for anomalous behavior, such as high frequencies of malformed request errors or internal server errors (500 status) occurring in persistent connection pools, which may indicate attempted exploitation or accidental triggering of this state.
- Prioritize patching for internet-facing systems that utilize persistent connections (keep-alive) for high-volume traffic.
