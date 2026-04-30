---
title: Juniper Junos OS MX Series Missing Authorization Vulnerability
slug: 2026-04-junos-mx-privesc
description: CVE-2026-33785 allows a low-privileged, local, authenticated user to execute 'request csds' commands on Juniper Junos OS MX Series devices, leading to complete device compromise.
date: "2026-04-09T22:16:27Z"
severities:
  - critical
type: advisory
types:
  - advisory
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

Juniper Networks Junos OS on MX Series is vulnerable to a missing authorization issue (CVE-2026-33785). This vulnerability allows a local, authenticated user with low privileges to execute specific CLI operational commands, specifically 'request csds', that should only be available to high-privileged users or those designated for Juniper Device Manager (JDM) / Connected Security Distributed Services (CSDS) operations. Successful exploitation leads to a complete compromise of managed devices. This issue affects Junos OS on MX Series versions 24.4 prior to 24.4R2-S3 and 25.2 prior to 25.2R2. Releases prior to 24.4 are not affected. The vulnerability was published on 2026-04-09.

## Attack Chain

1.  Attacker gains local, low-privilege access to a Junos OS MX Series device.
2.  Attacker authenticates to the Junos OS CLI using their credentials.
3.  Attacker executes the 'request csds' operational command.
4.  The system fails to perform adequate authorization checks before executing the command.
5.  The 'request csds' command executes with elevated privileges due to the missing authorization.
6.  Attacker leverages the elevated privileges to modify system configurations.
7.  Attacker installs malicious software or backdoors.
8.  Attacker achieves complete compromise of the Junos OS MX Series device, potentially impacting all devices managed by it.

## Impact

Successful exploitation of CVE-2026-33785 allows an attacker to completely compromise a Juniper Junos OS MX Series device. This can lead to unauthorized access to sensitive data, disruption of network services, and the potential compromise of other devices managed by the affected MX Series device. The vulnerability affects Junos OS on MX Series versions 24.4 before 24.4R2-S3 and 25.2 before 25.2R2. While the exact number of vulnerable devices is unknown, the impact is critical due to the potential for widespread network compromise.

## Recommendation

*   Upgrade Junos OS on MX Series devices to versions 24.4R2-S3 or later, or 25.2R2 or later, to patch CVE-2026-33785.
*   Implement the provided Sigma rule to detect unauthorized execution of the `request csds` command.
*   Monitor Junos OS CLI command logs for suspicious activity, specifically focusing on the `request csds` command and user privilege levels.
