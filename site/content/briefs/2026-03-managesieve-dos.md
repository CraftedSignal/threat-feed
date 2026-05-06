---
title: ManageSieve AUTHENTICATE Command Denial-of-Service Vulnerability (CVE-2025-59032)
slug: 2026-03-managesieve-dos
description: CVE-2025-59032 describes a vulnerability in ManageSieve's AUTHENTICATE command, where using a literal as a SASL initial response can crash the ManageSieve service, leading to a denial-of-service condition.
date: "2026-03-27T09:16:18Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - denial-of-service
  - managesieve
  - cve-2025-59032
  - mail-service
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-59032
  - https://documentation.open-xchange.com/dovecot/security/advisories/csaf/2026/oxdc-adv-2026-0001.json
rules:
  - title: Detect ManageSieve Service Crashes
    description: Detects repeated crashes of the ManageSieve service, potentially indicating exploitation of CVE-2025-59032.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
  - title: Detect ManageSieve Connections from Unusual Locations
    description: Detects connections to the ManageSieve port (4190) from unusual or unexpected IP addresses, which could indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2025-59032 is a denial-of-service vulnerability affecting ManageSieve services. The vulnerability occurs within the AUTHENTICATE command when processing a literal as the SASL initial response. An attacker can exploit this vulnerability by sending crafted requests that trigger a crash in the ManageSieve service. This can be done repeatedly, rendering the service unavailable to legitimate users. The vulnerability was reported to Open-Xchange and affects Dovecot-based ManageSieve…
