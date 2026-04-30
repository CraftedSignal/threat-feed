---
title: Free5GC AMF Denial-of-Service Vulnerability (CVE-2026-30653)
slug: 2026-03-free5gc-dos
description: A remote attacker can exploit CVE-2026-30653 in Free5GC v4.2.0 and earlier by sending crafted requests to the AMF component's HandleAuthenticationFailure function, leading to a denial-of-service condition.
date: "2026-03-24T15:16:34Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - free5gc
  - denial-of-service
  - cve-2026-30653
  - amf
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-30653
  - https://github.com/free5gc/free5gc/issues/826
rules:
  - title: Detect Suspicious Free5GC Authentication Failure Handling
    description: Detects potential attempts to exploit CVE-2026-30653 by monitoring for anomalous authentication failure handling patterns in Free5GC AMF logs.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect Free5GC AMF Excessive Resource Consumption
    description: Alerts on abnormal CPU or memory usage by the Free5GC AMF process, potentially indicating a DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Free5GC is an open-source 5G core network implementation. CVE-2026-30653 affects Free5GC versions 4.2.0 and earlier. The vulnerability resides within the Access and Mobility Management Function (AMF) component, specifically in the `HandleAuthenticationFailure` function. A remote, unauthenticated attacker can send malicious requests that trigger excessive resource consumption or a crash in the AMF, resulting in a denial-of-service (DoS) condition. This vulnerability was disclosed on March 24…
