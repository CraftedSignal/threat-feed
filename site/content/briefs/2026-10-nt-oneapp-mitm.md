---
brief_id: brief-2026-10-22-nt-oneapp-mitm
event_id: brief-2026-10-22-nt-oneapp-mitm
revision: 1
activity_at: "2026-10-22T06:00:27Z"
title: 'NewType Infortech NT OneAPP: Improper certificate validation vulnerability (CVE-2026-114220)'
slug: 2026-10-nt-oneapp-mitm
description: NT OneAPP fails to validate server certificates and hostnames, allowing network-adjacent attackers to conduct man-in-the-middle attacks.
date: "2026-10-22T06:00:27Z"
lastmod: "2026-10-22T06:00:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:newtype_infortech:nt_oneapp:*:*:*:*:*:*:*:*
tags:
  - credential-access
  - vulnerability
  - cve-2026-114219
vendors:
  - NewType Infortech
products:
  - NT OneAPP
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.004
    subtechnique_name: Private Keys
    evidence: Unauthenticated remote attackers can obtain the hard-coded cryptographic key and decrypt login request contents, thereby obtaining users plaintext account credentials and device information.
    confidence_band: high
cves:
  - id: CVE-2026-114220
    cvss: 9.1
    kev_status: "false"
  - id: CVE-2026-114219
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114220
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114219
updates:
  - at: "2026-10-22T06:00:48Z"
    level: L2
    summary: added coverage for NT OneAPP
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-114219
---

NT OneAPP, developed by NewType Infortech, contains an Improper Certificate Validation vulnerability (CVE-2026-114220). The application fails to validate the server certificate and the hostname. Consequently, unauthenticated network-adjacent attackers can perform a man-in-the-middle attack to intercept or modify communications between the application and the server.
