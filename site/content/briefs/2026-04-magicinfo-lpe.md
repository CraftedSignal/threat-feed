---
title: Samsung MagicINFO 9 Server Local Privilege Escalation via Incorrect Default Permissions (CVE-2026-25203)
slug: 2026-04-magicinfo-lpe
description: Samsung MagicINFO 9 Server versions prior to 21.1091.1 are susceptible to a local privilege escalation vulnerability due to incorrect default permissions, potentially allowing a low-privilege user to gain elevated privileges on the system.
date: "2026-04-10T02:16:02Z"
severities:
  - high
tags:
  - privilege-escalation
  - samsung
  - magicinfo
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-25203
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25203
  - https://security.samsungtv.com/securityUpdates
ioc_counts:
  email: 1
rules:
  - title: Detect MagicINFO Process Creation with Suspicious Arguments
    description: Detects potential exploitation attempts where MagicINFO processes are spawned with unusual command-line arguments indicative of privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect File Modifications in MagicINFO Directory
    description: Detects file creation or modification events within the MagicINFO installation directory, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-25203 describes a local privilege escalation vulnerability affecting Samsung MagicINFO 9 Server versions prior to 21.1091.1. The vulnerability stems from incorrect default permissions, which could allow a malicious actor with low-level access to elevate their privileges on the system. This could lead to unauthorized access to sensitive data, modification of system configurations, or even complete system compromise. The vulnerability was reported by Samsung TV & Appliance and impacts…
