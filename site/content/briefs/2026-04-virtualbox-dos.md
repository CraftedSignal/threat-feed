---
title: Oracle VirtualBox Unauthenticated RDP Denial-of-Service Vulnerability (CVE-2026-35245)
slug: 2026-04-virtualbox-dos
description: An unauthenticated attacker with network access via RDP can exploit CVE-2026-35245 in Oracle VM VirtualBox version 7.2.6 to cause a denial-of-service (DOS) condition.
date: "2026-04-21T21:16:40Z"
severities:
  - medium
tags:
  - virtualbox
  - rdp
  - dos
  - cve-2026-35245
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-35245
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35245
rules:
  - title: Detect Suspicious RDP Connections
    description: Detects RDP connections from unusual source IPs or to unusual destination ports that may indicate exploitation attempts targeting CVE-2026-35245.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Repeated RDP Connection Errors
    description: Detects repeated RDP connection errors to a host, which can indicate a denial-of-service attempt using malformed RDP requests.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-35245 is a vulnerability affecting Oracle VM VirtualBox version 7.2.6. This vulnerability resides in the Core component of VirtualBox and can be exploited by unauthenticated attackers with network access to the RDP service. Successful exploitation leads to a denial-of-service (DOS) condition, causing the VirtualBox application to hang or crash. The vulnerability's ease of exploitation makes it a significant threat to systems running vulnerable versions of VirtualBox exposed to…
