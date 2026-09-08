---
title: Multiple Vulnerabilities in Red Hat Enterprise Linux python-cryptography Package
slug: 2026-09-rhel-python-cryptography
description: Multiple vulnerabilities in the python-cryptography package for Red Hat Enterprise Linux, including CVE-2024-26130, may allow a remote, unauthenticated attacker to bypass security controls or cause a denial-of-service condition.
date: "2026-09-08T13:37:26Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cryptography.io:cryptography:*:*:*:*:*:python:*:*
tags:
  - vulnerability
  - linux
  - cryptography
vendors:
  - Red Hat
products:
  - Enterprise Linux (python-cryptography)
affected_os:
  - RHEL
cves:
  - id: CVE-2024-26130
    cvss: 7.5
    epss: 0.00831
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3214
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26130
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Update python-cryptography via the Red Hat package manager (yum or dnf) to the latest secure version.
      owner: IT Operations
      addresses: CVE-2024-26130
      evidence: Source advisory recommends standard patch management for the identified vulnerabilities.
---

The python-cryptography library included in Red Hat Enterprise Linux (RHEL) is affected by multiple security vulnerabilities, most notably CVE-2024-26130. These flaws stem from improper handling of specific cryptographic operations within the library. A remote, unauthenticated attacker could leverage these weaknesses to bypass security restrictions or trigger a denial-of-service (DoS) condition, potentially leading to application crashes or the compromise of integrity in services relying on affected cryptographic functions. Defenders should prioritize updating the python-cryptography package across all RHEL distributions, as it is a foundational library for many Python-based services and management utilities.

## Impact

Successful exploitation could lead to a denial-of-service, rendering impacted services unavailable, or the subversion of cryptographic protections intended to secure data in transit or at rest. All RHEL environments utilizing the affected library are at risk.

## Recommendation

Prioritize the identification and patching of systems running the affected python-cryptography versions. Use package management tools to audit installed versions and ensure the latest security updates provided by Red Hat are applied.
