---
title: HCL Aftermarket DPC Missing Access Control Vulnerability (CVE-2025-55261)
slug: 2024-01-hcl-dpc-privesc
description: A missing functional level access control vulnerability in HCL Aftermarket DPC (CVE-2025-55261) allows an attacker to escalate privileges, potentially compromising the application and leading to data theft or manipulation.
date: "2026-03-26T14:16:07Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - privilege-escalation
  - access-control
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-55261
  - https://support.hcl-software.com/csm?id=kb_article&sysparm_article=KB0129793
rules:
  - title: Detect Suspicious HCL DPC Access Attempts
    description: Detects attempts to access sensitive HCL DPC resources without proper authorization based on HTTP response codes.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect HCL DPC Configuration Changes via Web Request
    description: Detects suspicious web requests attempting to modify HCL DPC configurations, potentially indicating privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2025-55261 describes a critical vulnerability affecting HCL Aftermarket DPC. The vulnerability stems from a missing functional level access control, enabling an attacker to escalate their privileges within the application. This escalation could lead to a full compromise of the HCL Aftermarket DPC system. This vulnerability was published on March 26, 2026, and poses a significant risk to organizations utilizing the affected software. Successful exploitation could result in unauthorized…
