---
title: Vitals ESP Incorrect Authorization Vulnerability (CVE-2026-4639)
slug: 2026-03-vitals-esp-authz-bypass
description: CVE-2026-4639 is an Incorrect Authorization vulnerability in Galaxy Software Services' Vitals ESP, allowing authenticated remote attackers to perform administrative functions and escalate privileges.
date: "2026-03-24T05:16:25Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - incorrect-authorization
  - privilege-escalation
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4639
  - https://www.twcert.org.tw/en/cp-139-10795-25784-2.html
  - https://www.twcert.org.tw/tw/cp-132-10794-704a2-1.html
rules:
  - title: Detect VitalsESP Unauthorized Admin Access
    description: Detects attempts to access administrative URLs within Vitals ESP without proper authorization, indicating potential privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect VitalsESP Configuration Changes
    description: Detects attempts to modify configuration files or settings within Vitals ESP, which could indicate unauthorized changes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Vitals ESP, developed by Galaxy Software Services, is vulnerable to an Incorrect Authorization issue (CVE-2026-4639). This vulnerability allows attackers with valid user credentials to bypass authorization checks and execute administrative functions they should not have access to. The vulnerability was disclosed on March 24, 2026. An attacker could potentially gain complete control over the Vitals ESP system by exploiting this flaw. The vulnerable software and versions are not specified, so…
