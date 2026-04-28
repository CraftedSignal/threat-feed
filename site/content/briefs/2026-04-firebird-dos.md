---
title: Firebird Unauthenticated Denial-of-Service Vulnerability (CVE-2026-34232)
slug: 2026-04-firebird-dos
description: An unauthenticated attacker can cause a denial-of-service condition in Firebird database servers prior to versions 5.0.4, 4.0.7, and 3.0.14 by sending a crafted op_response packet that triggers a crash in the xdr_status_vector() function.
date: "2026-04-17T20:16:34Z"
severities:
  - high
tags:
  - cve-2026-34232
  - dos
  - firebird
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-34232
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34232
  - https://github.com/FirebirdSQL/firebird/releases/tag/v3.0.14
  - https://github.com/FirebirdSQL/firebird/releases/tag/v4.0.7
  - https://github.com/FirebirdSQL/firebird/releases/tag/v5.0.4
  - https://github.com/FirebirdSQL/firebird/security/advisories/GHSA-7jq3-6j3c-5cm2
rules:
  - title: Detect Firebird Server Crash
    description: Detects a Firebird server process crashing, potentially due to CVE-2026-34232 exploitation
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Unusual Network Traffic to Firebird Default Port
    description: Detects a spike in network traffic to the default Firebird port (3050) which might indicate a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Firebird is an open-source relational database management system. A vulnerability exists in versions prior to 5.0.4, 4.0.7, and 3.0.14. Specifically, the `xdr_status_vector()` function is susceptible to a flaw when decoding an `op_response` packet. The function fails to properly handle the `isc_arg_cstring` type within the status vector, leading to a server crash when encountered. This vulnerability, identified as CVE-2026-34232, can be exploited by an unauthenticated attacker who sends a…
