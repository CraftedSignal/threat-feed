---
title: Juniper Junos OS MX Series Missing Authorization Vulnerability
slug: 2026-04-junos-mx-privesc
description: CVE-2026-33785 allows a low-privileged, local, authenticated user to execute 'request csds' commands on Juniper Junos OS MX Series devices, leading to complete device compromise.
date: "2026-04-09T22:16:27Z"
severities:
  - critical
tags:
  - privilege-escalation
  - network
  - juniper
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33785
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33785
rules:
  - title: Detect Unauthorized Request CSDS Command Execution
    description: Detects execution of the 'request csds' command by low-privileged users on Juniper Junos OS
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - firewall
      - junos
  - title: Detect Junos Unauthorized Command Execution via Firewall Logs
    description: Detects attempts to execute unauthorized commands by monitoring firewall logs on Junos devices.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - firewall
      - junos
rules_count: 2
---

Juniper Networks Junos OS on MX Series is vulnerable to a missing authorization issue (CVE-2026-33785). This vulnerability allows a local, authenticated user with low privileges to execute specific CLI operational commands, specifically 'request csds', that should only be available to high-privileged users or those designated for Juniper Device Manager (JDM) / Connected Security Distributed Services (CSDS) operations. Successful exploitation leads to a complete compromise of managed devices…
