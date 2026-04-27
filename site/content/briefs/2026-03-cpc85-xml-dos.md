---
title: CPCI85 and SICORE Base System XML Out-of-Bounds Write Vulnerability
slug: 2026-03-cpc85-xml-dos
description: An unauthenticated attacker can exploit an out-of-bounds write vulnerability in CPCI85 Central Processing/Communication and SICORE Base System by sending a malicious XML request, potentially causing a service crash leading to a denial-of-service condition.
date: "2026-03-26T15:16:34Z"
severities:
  - high
tags:
  - cve-2026-27664
  - denial-of-service
  - xml
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27664
  - https://cert-portal.siemens.com/productcert/html/ssa-246443.html
rules:
  - title: Detect Suspicious XML Request Patterns
    description: Detects potentially malicious XML requests based on content patterns that may indicate exploit attempts.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect Service Crashes from XML Processing
    description: Detects service crashes potentially resulting from malicious XML processing based on process termination events.
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

A vulnerability, tracked as CVE-2026-27664, exists within CPCI85 Central Processing/Communication (all versions prior to V26.10) and SICORE Base system (all versions prior to V26.10.0). This flaw stems from an out-of-bounds write during the parsing of maliciously crafted XML inputs. An unauthenticated attacker could exploit this vulnerability by sending a specifically designed XML request to the targeted system. Successful exploitation results in a service crash, effectively creating a…
