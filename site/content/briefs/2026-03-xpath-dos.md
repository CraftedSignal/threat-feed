---
title: Denial of Service Vulnerability in github.com/antchfx/xpath (CVE-2026-4645)
slug: 2026-03-xpath-dos
description: A remote attacker can exploit CVE-2026-4645 in the `github.com/antchfx/xpath` component by submitting crafted Boolean XPath expressions, causing an infinite loop and leading to a denial-of-service condition with 100% CPU utilization.
date: "2026-03-23T14:16:36Z"
severities:
  - high
tags:
  - cve-2026-4645
  - denial-of-service
  - xpath
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.002
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4645
  - https://access.redhat.com/security/cve/CVE-2026-4645
  - https://bugzilla.redhat.com/show_bug.cgi?id=2450214
  - https://github.com/antchfx/xpath/commit/afd4762cc342af56345a3fb4002a59281fcab494
  - https://github.com/antchfx/xpath/issues/121
  - https://github.com/golang/vulndb/issues/4526
rules:
  - title: Detect XPath DoS via High CPU
    description: Detects processes that may be exploiting the XPath DoS vulnerability by monitoring for prolonged periods of high CPU usage.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - process_creation
      - linux
  - title: Detect XPath DoS via Repeated Errors
    description: Detects processes exhibiting repeated error messages indicative of a crafted XPath expression causing an infinite loop.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-4645 is a critical vulnerability found in the `github.com/antchfx/xpath` component. This flaw allows a remote, unauthenticated attacker to trigger a denial-of-service (DoS) condition. By sending specifically crafted Boolean XPath expressions, the attacker can force the `logicalQuery.Select` function into an infinite loop. This infinite loop results in the affected system's CPU utilization spiking to 100%, effectively rendering the system unresponsive and unavailable for legitimate…
