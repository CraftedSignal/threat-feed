---
title: Corosync Integer Overflow Vulnerability (CVE-2026-35092) Leads to DoS
slug: 2026-04-corosync-dos
description: CVE-2026-35092 is an integer overflow vulnerability in Corosync's join message sanity validation, allowing a remote, unauthenticated attacker to send crafted UDP packets, resulting in a denial of service condition.
date: "2026-04-01T14:16:57Z"
severities:
  - medium
tags:
  - cve-2026-35092
  - denial-of-service
  - corosync
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-35092
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35092
  - https://access.redhat.com/security/cve/CVE-2026-35092
  - https://bugzilla.redhat.com/show_bug.cgi?id=2453169
  - https://bugzilla.redhat.com/show_bug.cgi?id=2453814
rules:
  - title: Detect Suspicious Corosync UDP Traffic
    description: Detects potentially malicious UDP traffic targeting Corosync instances that may indicate an exploitation attempt of CVE-2026-35092.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
  - title: Detect Corosync Crash Events
    description: Detects when the Corosync service crashes, potentially due to exploitation of CVE-2026-35092
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-35092 describes an integer overflow vulnerability found in Corosync, a cluster engine. This vulnerability resides in the join message sanity validation process. A remote, unauthenticated attacker can exploit this flaw by sending specially crafted User Datagram Protocol (UDP) packets to a vulnerable Corosync instance. Successful exploitation leads to a service crash, effectively causing a denial of service (DoS). The vulnerability specifically targets Corosync deployments utilizing the…
