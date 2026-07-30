---
title: Multiple Vulnerabilities in GitLab
slug: 2026-07-gitlab-vulnerabilities
description: Multiple security vulnerabilities identified in GitLab CE and EE versions 19.x can result in remote denial of service, data confidentiality breaches, and reflected cross-site scripting.
date: "2026-07-30T15:26:07Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - vulnerability
  - gitlab
  - patch-management
vendors:
  - GitLab
products:
  - GitLab Community Edition
  - GitLab Enterprise Edition
cves:
  - id: CVE-2026-13113
    cvss: 6.5
    epss: 0.0021
  - id: CVE-2026-15077
    cvss: 4.3
    epss: 0.00245
  - id: CVE-2026-15831
    cvss: 4.3
    epss: 0.00236
  - id: CVE-2026-3093
    cvss: 4.7
    epss: 0.00238
  - id: CVE-2026-4672
    cvss: 4.3
    epss: 0.00243
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0946/
  - https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-2-1-released/
---

On July 30, 2026, the ANSSI and GitLab reported a set of security vulnerabilities affecting multiple versions of GitLab Community Edition (CE) and Enterprise Edition (EE). These flaws include critical bugs spanning CVE-2025-14562, CVE-2026-12436, CVE-2026-13113, CVE-2026-14341, CVE-2026-14351, CVE-2026-15077, CVE-2026-15831, CVE-2026-15975, CVE-2026-16553, CVE-2026-3093, CVE-2026-4672, CVE-2026-6267, and CVE-2026-6336. The vulnerabilities allow for remote denial-of-service conditions, unauthorized access to sensitive application data, and reflected cross-site scripting (XSS) attacks. Because these vulnerabilities are present in the core application logic across versions 19.0.x, 19.1.x, and 19.2.x, organizations are at risk of service disruption or data theft if they remain on unpatched builds. GitLab has released patches in versions 19.0.5, 19.1.3, and 19.2.1 to address these issues.

## Impact

Successful exploitation of these vulnerabilities could result in the loss of data confidentiality, the disruption of critical CI/CD pipelines through denial of service, and the potential for session hijacking or unauthorized actions performed on behalf of legitimate users via reflected XSS. Given that GitLab often acts as a central repository for source code and infrastructure-as-code, successful compromises represent a high risk to software supply chain integrity.

## Recommendation

- Upgrade all instances of GitLab CE and EE to versions 19.0.5, 19.1.3, or 19.2.1 immediately as specified in the GitLab security release documentation.
- Review web server access logs for anomalous patterns targeting standard GitLab endpoints, specifically focusing on unexpected parameters or script-like inputs that may indicate XSS injection attempts.
- Audit user activity logs for unexplained data access or session-related anomalies following the application of patches to ensure no prior exploitation occurred.
