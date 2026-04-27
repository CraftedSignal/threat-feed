---
title: Amazon Athena ODBC Driver Denial of Service Vulnerability (CVE-2026-35562)
slug: 2026-04-athena-odbc-dos
description: A remote, unauthenticated attacker can cause a denial of service by sending crafted input to vulnerable versions of the Amazon Athena ODBC driver, triggering excessive resource consumption during parsing operations.
date: "2026-04-03T21:17:12Z"
severities:
  - high
tags:
  - CVE-2026-35562
  - denial-of-service
  - amazon athena
  - odbc driver
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-35562
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35562
  - https://aws.amazon.com/security/security-bulletins/2026-013-aws/
  - https://docs.aws.amazon.com/athena/latest/ug/odbc-v2-driver-release-notes.html
rules:
  - title: Detect Excessive CPU Usage by Athena ODBC Driver
    description: Detects processes consuming excessive CPU resources, potentially indicating a denial-of-service attack against the Amazon Athena ODBC driver.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Excessive Memory Usage by Athena ODBC Driver
    description: Detects processes consuming excessive memory resources, potentially indicating a denial-of-service attack against the Amazon Athena ODBC driver.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A denial-of-service (DoS) vulnerability, tracked as CVE-2026-35562, affects the Amazon Athena ODBC driver. Specifically, versions prior to 2.1.0.0 are susceptible to unbounded resource allocation within their parsing components. An unauthenticated, remote attacker can exploit this weakness by sending specially crafted input to a system utilizing the vulnerable driver, leading to excessive resource consumption during parsing. This results in a denial of service condition, potentially impacting…
