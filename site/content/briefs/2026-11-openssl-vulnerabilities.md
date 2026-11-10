---
brief_id: brief-2026-11-10-openssl-vulnerabilities
event_id: brief-2026-11-10-openssl-vulnerabilities
revision: 1
activity_at: "2026-11-10T16:33:30Z"
title: 'OpenSSL: Multiple vulnerabilities (CVE-2026-107496, CVE-2026-88822, CVE-2026-88823, CVE-2026-95691, CVE-2026-95692)'
slug: 2026-11-openssl-vulnerabilities
description: Multiple vulnerabilities discovered in OpenSSL across multiple release branches allow for remote denial-of-service, data confidentiality breaches, and security policy bypasses.
date: "2026-11-10T16:33:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Patching required based on official vendor release.
tags:
  - vulnerability
  - openssl
  - cryptography
vendors:
  - OpenSSL
products:
  - OpenSSL (< 1.0.2zt)
  - OpenSSL (< 1.1.1zk)
  - OpenSSL (< 3.0.24)
  - OpenSSL (< 3.5.10)
  - OpenSSL (< 4.0.4)
  - OpenSSL (< 4.1.1)
cves:
  - id: CVE-2026-107496
    kev_status: unknown
  - id: CVE-2026-88822
    kev_status: unknown
  - id: CVE-2026-88823
    kev_status: unknown
  - id: CVE-2026-95691
    kev_status: unknown
  - id: CVE-2026-95692
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1496/
  - https://openssl-library.org/news/secadv/20261110.txt
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade all OpenSSL library versions to 1.0.2zt, 1.1.1zk, 3.0.24, 3.5.10, 4.0.4, 4.1.1 or higher.
      owner: IT Operations
      addresses: CVE-2026-107496, CVE-2026-88822, CVE-2026-88823, CVE-2026-95691, CVE-2026-95692
      evidence: Official OpenSSL security advisory of November 10, 2026.
---

The OpenSSL Project has released a security advisory addressing multiple vulnerabilities affecting the 1.0.2, 1.1.1, 3.0, 3.5, 4.0, and 4.1 release branches. These vulnerabilities may lead to remote denial-of-service, exposure of sensitive data, or bypass of security policies. Organizations should refer to the official OpenSSL security advisory for specific technical details and patch availability.

## Impact

Successful exploitation may allow attackers to disrupt service availability (DoS), gain unauthorized access to sensitive information, or circumvent established security controls.

## Recommendation

* Inventory all applications and services utilizing the OpenSSL library across the infrastructure.
* Patch all instances of OpenSSL to the identified secure versions or later: 1.0.2zt, 1.1.1zk, 3.0.24, 3.5.10, 4.0.4, or 4.1.1.
* Prioritize patching of internet-facing services or those handling sensitive user authentication and data.
