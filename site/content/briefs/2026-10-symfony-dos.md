---
title: Multiple Denial of Service Vulnerabilities in Symfony Framework
slug: 2026-10-symfony-dos
description: Multiple vulnerabilities across Symfony components, including expression-language, http-foundation, and yaml, enable remote attackers to cause a denial-of-service condition.
date: "2026-10-15T16:26:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - web-application
  - symfony
vendors:
  - Symfony
products:
  - expression-language (< 5.4.54, 6.x < 6.4.48, 7.x < 7.4.21, 8.x < 8.1.9)
  - http-foundation (< 5.4.54, 6.x < 6.4.46, 7.x < 7.4.19, 8.x < 8.1.7)
  - symfony (< 5.4.54, 6.x < 6.4.48, 7.x < 7.4.21, 8.x < 8.1.9)
  - yaml (< 5.4.54, 6.x < 6.4.45, 7.x < 7.4.18, 8.x < 8.1.6)
cves:
  - id: CVE-2026-108082
  - id: CVE-2026-109413
  - id: CVE-2026-109449
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1324/
  - https://github.com/symfony/symfony/security/advisories/GHSA-2v3c-qxhr-7vpv
  - https://github.com/symfony/symfony/security/advisories/GHSA-7rpj-w9pf-39rr
  - https://github.com/symfony/symfony/security/advisories/GHSA-r925-mgvr-h9cc
  - https://www.cve.org/CVERecord?id=CVE-2026-108082
  - https://www.cve.org/CVERecord?id=CVE-2026-109413
  - https://www.cve.org/CVERecord?id=CVE-2026-109449
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Update vulnerable Symfony components to the specified patched versions listed in the Recommendations section.
      owner: IT Operations
      addresses: CVE-2026-108082, CVE-2026-109413, CVE-2026-109449
      evidence: Source provides specific patched version numbers for each affected component.
---

Multiple vulnerabilities have been identified within the Symfony framework, specifically affecting the `expression-language`, `http-foundation`, and `yaml` components, as well as the core `symfony/symfony` package. These flaws impact various versions across the 5.4.x, 6.4.x, 7.4.x, and 8.1.x branches. The vulnerabilities are identified as CVE-2026-108082, CVE-2026-109413, and CVE-2026-109449. Successful exploitation of these vulnerabilities allows a remote attacker to induce a denial-of-service (DoS) condition on applications utilizing the vulnerable components, potentially rendering the service unavailable to legitimate users. Organizations running these versions of Symfony should prioritize updating to the patched versions provided by the vendor.

## Impact

The primary impact of these vulnerabilities is the disruption of service availability. Attackers can remotely trigger resource exhaustion or application crashes in systems relying on affected Symfony components. Given the prevalence of Symfony in modern PHP web development, any internet-facing application running unpatched versions is susceptible to DoS attacks.

## Recommendation

* Upgrade `symfony/expression-language` to 5.4.54, 6.4.48, 7.4.21, or 8.1.9 or later.
* Upgrade `symfony/http-foundation` to 5.4.54, 6.4.46, 7.4.19, or 8.1.7 or later.
* Upgrade `symfony/symfony` to 5.4.54, 6.4.48, 7.4.21, or 8.1.9 or later.
* Upgrade `symfony/yaml` to 5.4.54, 6.4.45, 7.4.18, or 8.1.6 or later.
* Review the specific GitHub Security Advisories linked in the Documentation section of the CERT-FR report to understand the specific triggers for the DoS conditions in your environment.
