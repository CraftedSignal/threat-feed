---
title: Multiple Vulnerabilities in GitLab CE and EE
slug: 2026-09-gitlab-vulnerabilities
description: GitLab has released security patches addressing a large set of vulnerabilities across Community and Enterprise editions, including flaws leading to remote code execution and data confidentiality compromises.
date: "2026-09-11T18:55:51Z"
lastmod: "2026-09-12T00:50:03Z"
type: advisory
types:
  - advisory
severities:
  - high
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
  - GitLab Community Edition
  - GitLab Enterprise Edition
  - Community Edition
  - Enterprise Edition
cves:
  - id: CVE-2026-85706
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1160/
  - https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-3-2-released/
  - https://www.cisa.gov/news-events/alerts/2026/09/11/cisa-adds-one-known-exploited-vulnerability-catalog
  - https://sploitus.com/exploit?id=CB41C932-3F63-547C-8278-6162A20CA9E3&utm_source=rss&utm_medium=rss
  - https://www.cve.org/CVERecord?id=CVE-2026-85706
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
---

On September 10, 2026, GitLab released critical security patches for its Community Edition (CE) and Enterprise Edition (EE) platforms. The update addresses a significant number of vulnerabilities reported by the CERT-FR in advisory CERTFR-2026-AVI-1160. These vulnerabilities affect GitLab versions prior to 19.1.8, as well as 19.2.x prior to 19.2.6, and 19.3.x prior to 19.3.2. 

The disclosed flaws include critical impacts such as remote code execution (RCE), denial-of-service (DoS), security policy bypasses, and unauthorized access to sensitive data. Given the breadth of vulnerabilities - ranging from RCE to cross-site scripting (XSS) - these patches are essential to maintain the integrity of development environments and source code repositories. Defenders should prioritize auditing internet-facing GitLab instances for these versions and applying the security patches immediately to mitigate the risk of exploitation.

## Impact

Successful exploitation of these vulnerabilities could result in full system compromise, exfiltration of proprietary source code, internal network reconnaissance, or localized denial-of-service, impacting the development lifecycle and data confidentiality for any organization running affected GitLab versions.

## Recommendation

- Upgrade all instances of GitLab Community Edition and Enterprise Edition to the latest patched versions: 19.1.8, 19.2.6, or 19.3.2 as specified in the official GitLab security release.
- Review web server access logs for anomalous POST requests or unusual URI patterns targeting common GitLab endpoints, which could indicate exploitation attempts against these CVEs.
- Patch the following CVEs: CVE-2024-11222, CVE-2025-14871, CVE-2026-1168, CVE-2026-12910, CVE-2026-13210, CVE-2026-16794, CVE-2026-19619, CVE-2026-3855, CVE-2026-7514, CVE-2026-78252, CVE-2026-79708, CVE-2026-8030, CVE-2026-82837, CVE-2026-85706, CVE-2026-86340, CVE-2026-86341, CVE-2026-87719, and CVE-2026-88765.
