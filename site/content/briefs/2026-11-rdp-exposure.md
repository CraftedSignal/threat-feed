---
brief_id: brief-2026-11-05-rdp-exposure
event_id: brief-2026-11-05-rdp-exposure
revision: 1
activity_at: "2026-11-05T14:26:12Z"
title: Detection of External RDP Logon from Public IP Addresses
slug: 2026-11-rdp-exposure
description: This detection identifies successful Remote Desktop Protocol (RDP) logons originating from non-private IP addresses, which may indicate a publicly-exposed RDP port.
date: "2026-11-05T14:26:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.privilege-escalation
  - attack.persistence
  - attack.initial-access
  - attack.credential-access
  - attack.stealth
  - attack.t1133
  - attack.t1078
  - attack.t1110
references:
  - https://www.inversecos.com/2020/04/successful-4624-anonymous-logons-to.html
  - https://twitter.com/Purp1eW0lf/status/1616144561965002752
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_successful_external_remote_rdp_login.yml
rules:
  - title: Detect Successful External Remote RDP Logon
    description: Detects successful logon from public IP address via RDP.
    platform: sigma
    severity: medium
    data_sources:
      - windows
      - security
rules_count: 1
---

Successful RDP logons (LogonType 10) from public IP addresses can indicate that a Windows host has a publicly-exposed RDP port. 

## False Positives
Legitimate or intentional inbound connections from public IP addresses on the RDP port.
