---
title: Multiple Vulnerabilities in OpenSSL
slug: 2026-08-openssl-vulnerabilities
description: Multiple vulnerabilities across several OpenSSL branches allow remote attackers to cause denial of service or bypass security policies.
date: "2026-08-26T13:58:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
products:
  - OpenSSL 1.0.2
  - OpenSSL 1.1.1
  - OpenSSL 3.0
  - OpenSSL 3.4
  - OpenSSL 3.5
  - OpenSSL 3.6
  - OpenSSL 4.0
cves:
  - id: CVE-2026-14457
    cvss: 7.5
  - id: CVE-2026-18798
    cvss: 7.5
  - id: CVE-2026-54874
    cvss: 7.5
  - id: CVE-2026-63072
    cvss: 7.5
  - id: CVE-2026-63073
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1079/
  - https://openssl-library.org/news/secadv/20260825.txt
  - https://www.cve.org/CVERecord?id=CVE-2026-14457
  - https://www.cve.org/CVERecord?id=CVE-2026-18798
  - https://www.cve.org/CVERecord?id=CVE-2026-54874
  - https://www.cve.org/CVERecord?id=CVE-2026-63072
  - https://www.cve.org/CVERecord?id=CVE-2026-63073
  - https://www.cve.org/CVERecord?id=CVE-2026-63074
  - https://www.cve.org/CVERecord?id=CVE-2026-63075
  - https://www.cve.org/CVERecord?id=CVE-2026-63076
  - https://www.cve.org/CVERecord?id=CVE-2026-75803
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Patch OpenSSL libraries to the recommended versions
      owner: IT Operations
      addresses: CVE-2026-14457, CVE-2026-18798, CVE-2026-54874, CVE-2026-63072, CVE-2026-63073, CVE-2026-63074, CVE-2026-63075, CVE-2026-63076, CVE-2026-75803
      evidence: OpenSSL security advisory dated 2026-08-25
---

The OpenSSL project has released a security advisory addressing multiple vulnerabilities affecting several legacy and current versions of the OpenSSL cryptographic library. These vulnerabilities allow remote attackers to trigger denial of service (DoS) conditions or bypass established security policies. Affected branches include 1.0.2, 1.1.1, 3.0, 3.4, 3.5, 3.6, and 4.0. Given the ubiquity of OpenSSL in enterprise infrastructure, including web servers, load balancers, VPNs, and application runtimes, these vulnerabilities present a significant risk. Defenders should prioritize auditing systems for the specific vulnerable versions and applying the updates outlined in the OpenSSL security advisory dated August 25, 2026.

## Impact

Successful exploitation of these vulnerabilities could result in the disruption of services due to DoS or the potential bypass of security controls, such as cryptographic validation or authentication mechanisms. Given that OpenSSL is a foundational library, the impact of these vulnerabilities spans nearly all sectors that utilize secure communications and encryption.

## Recommendation

- Identify all instances of OpenSSL within the environment, including those bundled with third-party applications, using software composition analysis (SCA) tools or file system inventory.
- Upgrade all instances of OpenSSL to the patched versions as specified in the August 25, 2026, OpenSSL advisory: 1.0.2zr, 1.1.1zi, 3.0.22, 3.4.7, 3.5.8, 3.6.4, or 4.0.2.
- Monitor vendor security portals for applications that depend on these affected OpenSSL versions to ensure timely updates are applied once they become available.
- Prioritize patching of internet-facing services and critical security infrastructure.
