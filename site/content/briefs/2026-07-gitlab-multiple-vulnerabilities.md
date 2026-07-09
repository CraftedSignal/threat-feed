---
title: Multiple Vulnerabilities Discovered in GitLab CE/EE
slug: 2026-07-gitlab-multiple-vulnerabilities
description: Multiple vulnerabilities have been discovered in GitLab Community Edition (CE) and Enterprise Edition (EE) across versions 19.0.x, 19.1.x, and 18.11.x, allowing an attacker to compromise data confidentiality, inject remote code via Cross-Site Scripting (XSS) (CVE-2026-11827), and bypass security policies (CVE-2026-13320).
date: "2026-07-09T14:28:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - vulnerability
  - gitlab
  - xss
  - data-leak
vendors:
  - GitLab
products:
  - GitLab Community Edition (CE) < 18.11.7
  - GitLab Enterprise Edition (EE) < 18.11.7
  - GitLab Community Edition (CE) < 19.0.4
  - GitLab Enterprise Edition (EE) < 19.0.4
  - GitLab Community Edition (CE) < 19.1.2
  - GitLab Enterprise Edition (EE) < 19.1.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Une injection de code indirecte à distance (XSS)
    confidence_band: high
cves:
  - id: CVE-2026-11827
    cvss: 4.9
  - id: CVE-2026-13320
    cvss: 7.3
  - id: CVE-2026-13151
    cvss: 2.7
  - id: CVE-2026-6352
    cvss: 2.7
  - id: CVE-2026-6896
    cvss: 8.7
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0850/
  - https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-1-2-released/
  - https://www.cve.org/CVERecord?id=CVE-2025-12506
  - https://www.cve.org/CVERecord?id=CVE-2026-11827
  - https://www.cve.org/CVERecord?id=CVE-2026-13151
  - https://www.cve.org/CVERecord?id=CVE-2026-13320
  - https://www.cve.org/CVERecord?id=CVE-2026-6352
  - https://www.cve.org/CVERecord?id=CVE-2026-6896
  - https://www.cve.org/CVERecord?id=CVE-2026-7492
  - https://www.cve.org/CVERecord?id=CVE-2026-8472
---

Multiple critical and high-severity vulnerabilities, including CVE-2025-12506, CVE-2026-11827, CVE-2026-13151, CVE-2026-13320, CVE-2026-6352, CVE-2026-6896, CVE-2026-7492, and CVE-2026-8472, have been identified in GitLab Community Edition (CE) and Enterprise Edition (EE). These flaws impact versions 19.0.x prior to 19.0.4, 19.1.x prior to 19.1.2, and all versions prior to 18.11.7. These vulnerabilities could enable an attacker to achieve data confidentiality compromise, perform indirect remote code injection through Cross-Site Scripting (XSS), and bypass existing security policies. The CERT-FR issued an advisory on July 9, 2026, based on a GitLab security bulletin from July 8, 2026, urging users to apply patches immediately. The discovery highlights the ongoing need for vigilant patch management in web-based version control systems.

## Impact

Successful exploitation of these vulnerabilities could lead to significant unauthorized access and control over GitLab instances. An attacker could exfiltrate sensitive data, manipulate user interfaces or execute arbitrary code in a victim's browser through XSS, potentially leading to session hijacking or further compromise. Furthermore, security policy bypasses could undermine an organization's defensive measures, granting attackers persistent access or enabling broader network penetration. The nature of these vulnerabilities, particularly in a critical development platform like GitLab, poses a substantial risk to intellectual property, code integrity, and operational continuity for affected organizations.

## Recommendation

* Immediately apply the security patches provided by GitLab for all affected versions of GitLab Community Edition (CE) and Enterprise Edition (EE) as referenced in the GitLab security bulletin (https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-1-2-released/).
* Specifically, update GitLab CE/EE to version 19.0.4 or later if currently on 19.0.x, to 19.1.2 or later if on 19.1.x, and to 18.11.7 or later if on versions prior to 18.11.7.
* Review web application firewall (WAF) configurations to potentially detect and block unusual requests targeting common XSS vectors, specifically for CVE-2026-11827.
