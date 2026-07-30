---
title: Authentication Bypass Vulnerability in IBM WebSphere Application Server
slug: 2026-07-websphere-auth-bypass
description: A critical authentication bypass vulnerability (CVE-2026-10842) allows remote, unauthenticated attackers to circumvent security constraints in IBM WebSphere Application Server and Liberty versions.
date: "2026-07-30T17:29:55Z"
lastmod: "2026-07-30T21:31:47Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - IBM
products:
  - WebSphere Application Server (8.5, 9.0)
  - WebSphere Application Server - Liberty (17.0.0.3 - 26.0.0.7)
  - WebSphere Application Server (9.0, 8.5)
cves:
  - id: CVE-2026-10842
    cvss: 7.5
  - id: CVE-2026-9322
    cvss: 7.5
references:
  - https://www.ibm.com/support/pages/node/7280131
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10842
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9322
  - https://www.ibm.com/support/pages/node/7278576
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11536
updates:
  - at: "2026-07-30T17:30:18Z"
    level: L1
    summary: 'merged source coverage: Denial of Service Vulnerability in IBM WebSphere Application Server'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-9322
  - at: "2026-07-30T21:31:47Z"
    level: L2
    summary: added CVE-2026-9322
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-11536
---

IBM has disclosed a security vulnerability, CVE-2026-10842, identified as an authentication bypass via alternate name (CWE-289). This vulnerability affects IBM WebSphere Application Server versions 8.5 and 9.0, as well as IBM WebSphere Application Server - Liberty versions 17.0.0.3 through 26.0.0.7. The flaw permits a remote, unauthenticated attacker to bypass established security constraints, potentially leading to unauthorized access to sensitive application resources or administrative functions. Given the base CVSS score of 7.5, this vulnerability represents a significant risk to enterprise environments where WebSphere serves as a critical middleware component. Defenders should prioritize patching affected instances and monitoring for unusual traffic patterns targeting authentication-related endpoints or administrative interfaces.

## Impact

Successful exploitation of CVE-2026-10842 allows for complete bypass of security controls enforced by the affected WebSphere instances. This could lead to unauthorized data access, potential compromise of internal business logic, or exposure of administrative interfaces to unauthenticated remote actors. The vulnerability impacts widespread enterprise deployments of WebSphere, posing a risk of data exfiltration and loss of integrity for business-critical applications.

## Recommendation

Prioritize the application of vendor-supplied patches as detailed in the IBM security bulletin.

- Apply the security patches or upgrade to the non-vulnerable versions specified in the IBM support document provided in the references.
- Review access logs for web applications hosted on affected WebSphere instances to identify spikes in 401 or 403 status codes followed by successful access to sensitive resources.
- Audit administrative and application-level access controls to identify any bypassed security constraints.
