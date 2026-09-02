---
title: Multiple Vulnerabilities in Curl
slug: 2026-09-curl-vulnerabilities
description: Multiple vulnerabilities were discovered in the Curl library (versions 7.44.0 through 8.21.x), potentially allowing attackers to compromise data integrity, confidentiality, or bypass security policies.
date: "2026-09-02T18:02:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - library
  - patch-management
vendors:
  - curl
products:
  - Curl (7.44.0 <= version < 8.22.0)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1108/
  - https://curl.se/docs/CVE-2026-13608.html
  - https://curl.se/docs/CVE-2026-18924.html
  - https://curl.se/docs/CVE-2026-19931.html
  - https://curl.se/docs/CVE-2026-80229.html
  - https://curl.se/docs/CVE-2026-80230.html
  - https://curl.se/docs/CVE-2026-80231.html
  - https://curl.se/docs/CVE-2026-80255.html
  - https://curl.se/docs/CVE-2026-82208.html
  - https://curl.se/docs/CVE-2026-82209.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Curl to version 8.22.0 or later
      owner: IT Operations
      addresses: CVE-2026-13608, CVE-2026-18924, CVE-2026-19931, CVE-2026-80229, CVE-2026-80230, CVE-2026-80231, CVE-2026-80255, CVE-2026-82208, CVE-2026-82209
      evidence: Vendor security bulletins and ANSSI advisory
---

The French National Cybersecurity Agency (ANSSI) has issued an advisory regarding multiple security vulnerabilities discovered in the Curl library. The affected versions range from 7.44.0 up to, but not including, 8.22.0. These vulnerabilities present risks to data integrity and confidentiality, and may allow attackers to bypass established security policies. Given Curl's ubiquitous use as a foundational networking component across various operating systems and enterprise applications, these vulnerabilities are significant. Organizations should identify systems relying on older versions of Curl and prioritize patching to version 8.22.0 or higher to mitigate these risks.

## Impact

Successful exploitation of these vulnerabilities can lead to unauthorized access to sensitive data, modification of data in transit or at rest, and the circumvention of security controls. Because Curl is often bundled within diverse software stacks, the potential impact spans a broad range of sectors including cloud infrastructure, web services, and endpoint software.

## Recommendation

* Prioritize the identification and patching of all software distributions and services utilizing Curl versions between 7.44.0 and 8.21.x.
* Upgrade all identified instances to Curl version 8.22.0 or the latest stable version provided by your distribution maintainers.
* Audit application dependencies to ensure underlying libraries are updated, as many applications embed Curl rather than utilizing system-level installations.
* Consult the upstream vendor security bulletins for CVE-2026-13608, CVE-2026-18924, CVE-2026-19931, CVE-2026-80229, CVE-2026-80230, CVE-2026-80231, CVE-2026-80255, CVE-2026-82208, and CVE-2026-82209 for specific technical remediation guidance.
