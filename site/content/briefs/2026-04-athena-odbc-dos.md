---
title: Amazon Athena ODBC Driver Denial of Service Vulnerability (CVE-2026-35562)
slug: 2026-04-athena-odbc-dos
description: A remote, unauthenticated attacker can cause a denial of service by sending crafted input to vulnerable versions of the Amazon Athena ODBC driver, triggering excessive resource consumption during parsing operations.
date: "2026-04-03T21:17:12Z"
severities:
  - high
type: advisory
types:
  - advisory
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

A denial-of-service (DoS) vulnerability, tracked as CVE-2026-35562, affects the Amazon Athena ODBC driver. Specifically, versions prior to 2.1.0.0 are susceptible to unbounded resource allocation within their parsing components. An unauthenticated, remote attacker can exploit this weakness by sending specially crafted input to a system utilizing the vulnerable driver, leading to excessive resource consumption during parsing. This results in a denial of service condition, potentially impacting availability of applications relying on the Athena ODBC driver. The vulnerability was publicly disclosed on April 3, 2026, and defenders should prioritize upgrading to version 2.1.0.0 or later.

## Attack Chain

1.  The attacker identifies a system utilizing a vulnerable version of the Amazon Athena ODBC driver (versions prior to 2.1.0.0).
2.  The attacker crafts malicious input designed to trigger excessive resource consumption in the driver's parsing component.
3.  The attacker sends the crafted input to the target system via a network connection. The delivery method depends on how the ODBC driver is integrated into the target application.
4.  The Athena ODBC driver receives the malicious input and begins parsing it.
5.  Due to the unbounded resource allocation vulnerability, the driver consumes excessive CPU and memory resources while parsing the crafted input.
6.  The excessive resource consumption leads to a slowdown or crash of the ODBC driver and any applications relying on it.
7.  The target system becomes unresponsive or experiences significant performance degradation, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-35562 can result in a denial-of-service condition, impacting any applications that rely on the vulnerable Amazon Athena ODBC driver. This can lead to service disruption, data unavailability, and potential financial losses. While the exact number of affected organizations is unknown, any organization utilizing affected versions of the Athena ODBC driver is potentially at risk.

## Recommendation

*   Immediately upgrade all instances of the Amazon Athena ODBC driver to version 2.1.0.0 or later to remediate CVE-2026-35562.
*   Monitor systems utilizing the Amazon Athena ODBC driver for abnormal resource consumption, which may indicate exploitation attempts.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
