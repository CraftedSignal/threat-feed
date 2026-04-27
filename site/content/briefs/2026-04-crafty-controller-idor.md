---
title: Crafty Controller Users API Insecure Direct Object Reference Vulnerability
slug: 2026-04-crafty-controller-idor
description: Crafty Controller's Users API component contains an insecure direct object reference vulnerability, allowing a remote, authenticated attacker to perform unauthorized user modification actions due to improper API permissions validation (CVE-2026-5652).
date: "2026-04-21T17:16:57Z"
severities:
  - critical
tags:
  - idor
  - privilege-escalation
  - cve-2026-5652
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5652
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5652
  - https://gitlab.com/crafty-controller/crafty-4/-/work_items/705
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious User Modification via API
    description: Detects attempts to modify user accounts via the Users API using IDs that don't match the authenticated user.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Crafty Controller User API Modification
    description: Detects user modification activity within Crafty Controller's API endpoints.
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

An insecure direct object reference (IDOR) vulnerability has been identified in the Users API component of Crafty Controller. This flaw, designated as CVE-2026-5652, allows a remote, authenticated attacker to bypass authorization controls and perform unauthorized user modification actions. The vulnerability stems from improper API permissions validation, enabling malicious actors with valid credentials but insufficient privileges to manipulate user accounts beyond their authorized scope. This…
