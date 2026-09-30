---
title: Multiple Vulnerabilities in OpenSSL
slug: 2026-09-openssl-vulnerabilities
description: Multiple security flaws in various OpenSSL versions allow remote attackers to perform denial of service, compromise confidentiality, and breach data integrity.
date: "2026-09-30T16:19:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - openssl
  - patch-management
vendors:
  - OpenSSL
products:
  - OpenSSL (1.0.2x < 1.0.2zs)
  - OpenSSL (1.1.1x < 1.1.1zj)
  - OpenSSL (3.0.x < 3.0.23)
  - OpenSSL (3.4.x < 3.4.8)
  - OpenSSL (3.5.x < 3.5.9)
  - OpenSSL (3.6.x < 3.6.5)
  - OpenSSL (4.0.x < 4.0.3)
cves:
  - id: CVE-2026-42772
  - id: CVE-2026-54872
    cvss: 3.7
  - id: CVE-2026-54873
  - id: CVE-2026-54875
    cvss: 3.7
  - id: CVE-2026-75805
    cvss: 5.3
  - id: CVE-2026-84782
    cvss: 8.2
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1241/
  - https://openssl-library.org/news/secadv/20260929.txt
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory all systems for vulnerable OpenSSL versions
      owner: Security Engineering
      due: 24h
      evidence: Source bulletin lists multiple vulnerable versions requiring updates
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenSSL to the latest indicated patch versions
      owner: IT Operations
      addresses: CVE-2026-35189, CVE-2026-35191, CVE-2026-42772, CVE-2026-54872, CVE-2026-54873, CVE-2026-54875, CVE-2026-72897, CVE-2026-75804, CVE-2026-75805, CVE-2026-75806, CVE-2026-77696, CVE-2026-84782, CVE-2026-84783, CVE-2026-84784
      evidence: Official OpenSSL security advisory of September 29, 2026
---

The OpenSSL project has released security advisories addressing multiple vulnerabilities across several versions of its library, ranging from legacy releases to current development branches. These vulnerabilities, identified as CVE-2026-35189, CVE-2026-35191, CVE-2026-42772, CVE-2026-54872, CVE-2026-54873, CVE-2026-54875, CVE-2026-72897, CVE-2026-75804, CVE-2026-75805, CVE-2026-75806, CVE-2026-77696, CVE-2026-84782, CVE-2026-84783, and CVE-2026-84784, enable a variety of attack vectors. Depending on the specific flaw, remote attackers may be able to induce denial-of-service conditions through resource exhaustion or crash-inducing malformed inputs, bypass security policies, or compromise the confidentiality and integrity of encrypted communications. Given the widespread use of OpenSSL in critical infrastructure, web servers, and distributed systems, these vulnerabilities pose a significant risk of service disruption and unauthorized data access across diverse enterprise environments.

## Impact

Successful exploitation of these vulnerabilities can lead to full service downtime for applications relying on the vulnerable OpenSSL library, the exposure of sensitive session data or keys, and the potential for unauthorized manipulation of data flows. Due to the nature of cryptographic libraries, any service using these versions is potentially exposed. Organizations should prioritize updating affected software packages to the latest patched versions as detailed in the official OpenSSL security bulletin to mitigate these risks.

## Recommendation

Prioritize the identification and patching of all instances of OpenSSL using the versions specified in the affected products list. 

- Perform an inventory of all systems to identify vulnerable OpenSSL versions using local package managers or binary scanners.
- Apply the updates provided by your OS distribution or software vendor to the fixed versions listed in the official OpenSSL advisory.
- Upgrade affected components to: OpenSSL 1.0.2zs, 1.1.1zj, 3.0.23, 3.4.8, 3.5.9, 3.6.5, or 4.0.3.
- Monitor for increased error rates or unexpected service terminations in applications linked against OpenSSL, which may indicate exploitation attempts.
