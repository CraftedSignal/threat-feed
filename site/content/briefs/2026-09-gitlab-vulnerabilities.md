---
brief_id: brief-2026-09-gitlab-vulnerabilities
event_id: brief-2026-09-gitlab-vulnerabilities
revision: 1
activity_at: "2026-09-11T18:55:51Z"
title: Multiple Vulnerabilities in GitLab CE and EE
slug: 2026-09-gitlab-vulnerabilities
description: GitLab has released security patches addressing a large set of vulnerabilities across Community and Enterprise editions, including flaws leading to remote code execution and data confidentiality compromises.
date: "2026-09-11T18:55:51Z"
lastmod: "2026-09-14T19:10:33Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source corroborated by vendor documentation.
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CB41C932-3F63-547C-8278-6162A20CA9E3&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - remote-code-execution
  - gitlab
vendors:
  - GitLab
products:
  - GitLab Community Edition (< 19.1.8, 19.2.x < 19.2.6, 19.3.x < 19.3.2)
  - GitLab Enterprise Edition (< 19.1.8, 19.2.x < 19.2.6, 19.3.x < 19.3.2)
  - GitLab Community Edition (< 19.1.8)
  - GitLab Enterprise Edition
  - Community Edition (< 19.1.8)
  - Enterprise Edition (< 19.1.8)
  - GitLab Community Edition (>= 18.7, < 19.1.8, >= 19.2, < 19.2.6, >= 19.3, < 19.3.2)
  - GitLab Enterprise Edition (>= 18.7, < 19.1.8, >= 19.2, < 19.2.6, >= 19.3, < 19.3.2)
cves:
  - id: CVE-2026-87719
    cvss: 9.9
    epss: 0.00612
    kev_status: unknown
  - id: CVE-2026-85706
    kev_status: unknown
  - id: CVE-2024-11222
    kev_status: unknown
  - id: CVE-2025-14871
    kev_status: unknown
  - id: CVE-2026-1168
    kev_status: unknown
  - id: CVE-2026-12910
    kev_status: unknown
  - id: CVE-2026-13210
    kev_status: unknown
  - id: CVE-2026-16794
    kev_status: unknown
  - id: CVE-2026-19619
    kev_status: unknown
  - id: CVE-2026-3855
    kev_status: unknown
  - id: CVE-2026-7514
    kev_status: unknown
  - id: CVE-2026-78252
    kev_status: unknown
  - id: CVE-2026-79708
    kev_status: unknown
  - id: CVE-2026-8030
    kev_status: unknown
  - id: CVE-2026-82837
    kev_status: unknown
  - id: CVE-2026-86340
    kev_status: unknown
  - id: CVE-2026-86341
    kev_status: unknown
  - id: CVE-2026-88765
    kev_status: unknown
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/
  - https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-3-2-released/
  - https://www.cisa.gov/news-events/alerts/2026/09/11/cisa-adds-one-known-exploited-vulnerability-catalog
  - https://sploitus.com/exploit?id=CB41C932-3F63-547C-8278-6162A20CA9E3&utm_source=rss&utm_medium=rss
  - https://www.cve.org/CVERecord?id=CVE-2026-85706
  - https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild
  - https://socprime.com/blog/cve-2026-85706-critical-gitlab-path-traversal-flaw/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade GitLab instances to versions 19.1.8, 19.2.6, or 19.3.2.
      owner: IT Operations
      due: 24h
      evidence: GitLab security bulletin provided in CERT-FR advisory.
  mitigation_plan:
    - priority: immediate
      action: Patch GitLab to 19.1.8, 19.2.6, or 19.3.2.
      owner: IT Operations
      addresses: Multiple CVEs
      evidence: Source documentation for patch release.
updates:
  - at: "2026-09-11T21:27:13Z"
    level: L2
    summary: added CVE-2026-85706
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/alerts/2026/09/11/cisa-adds-one-known-exploited-vulnerability-catalog
  - at: "2026-09-11T23:36:56Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CB41C932-3F63-547C-8278-6162A20CA9E3&utm_source=rss&utm_medium=rss
  - at: "2026-09-12T00:50:03Z"
    level: L1
    summary: new product
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-85706
  - at: "2026-09-14T19:10:33Z"
    level: L2
    summary: added CVE-2026-87719;
    sources:
      - socprime
    source_urls:
      - https://socprime.com/blog/cve-2026-85706-critical-gitlab-path-traversal-flaw/
---

On September 10, 2026, GitLab released critical security patches for its Community Edition (CE) and Enterprise Edition (EE) platforms. The update addresses a significant number of vulnerabilities reported by the CERT-FR in advisory CERTFR-2026-AVI-1160. These vulnerabilities affect GitLab versions prior to 19.1.8, as well as 19.2.x prior to 19.2.6, and 19.3.x prior to 19.3.2.

The disclosed flaws include critical impacts such as remote code execution (RCE), denial-of-service (DoS), security policy bypasses, and unauthorized access to sensitive data. Given the breadth of vulnerabilities - ranging from RCE to cross-site scripting (XSS) - these patches are essential to maintain the integrity of development environments and source code repositories. Defenders should prioritize auditing internet-facing GitLab instances for these versions and applying the security patches immediately to mitigate the risk of exploitation.

## Impact

Successful exploitation of these vulnerabilities could result in full system compromise, exfiltration of proprietary source code, internal network reconnaissance, or localized denial-of-service, impacting the development lifecycle and data confidentiality for any organization running affected GitLab versions.

## Recommendation

- Upgrade all instances of GitLab Community Edition and Enterprise Edition to the latest patched versions: 19.1.8, 19.2.6, or 19.3.2 as specified in the official GitLab security release.
- Review web server access logs for anomalous POST requests or unusual URI patterns targeting common GitLab endpoints, which could indicate exploitation attempts against these CVEs.
- Patch the following CVEs: CVE-2024-11222, CVE-2025-14871, CVE-2026-1168, CVE-2026-12910, CVE-2026-13210, CVE-2026-16794, CVE-2026-19619, CVE-2026-3855, CVE-2026-7514, CVE-2026-78252, CVE-2026-79708, CVE-2026-8030, CVE-2026-82837, CVE-2026-85706, CVE-2026-86340, CVE-2026-86341, CVE-2026-87719, and CVE-2026-88765.
