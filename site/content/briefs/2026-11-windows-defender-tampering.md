---
brief_id: brief-2026-11-25-windows-defender-tampering
event_id: brief-2026-11-25-windows-defender-tampering
revision: 1
activity_at: "2026-11-25T16:34:29Z"
title: 'Windows Defender: Unauthorized modification of protection registry keys'
slug: 2026-11-windows-defender-tampering
description: Attackers or tools can disable Windows Defender functionalities by modifying specific registry keys.
date: "2026-11-25T16:34:29Z"
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
  - attack.defense-impairment
  - attack.t1685
  - windows
  - registry
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_windows_defender_tamper.yml
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://web.archive.org/web/20211121135248/https://gist.github.com/anadr/7465a9fde63d41341136949f14c21105
  - https://admx.help/?Category=Windows_7_2008R2&Policy=Microsoft.Policies.WindowsDefender::SpyNetReporting
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
  - https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.html
  - https://www.tenforums.com/tutorials/105533-enable-disable-windows-defender-exploit-protection-settings.html
  - https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-microsoft-defender-antivirus.html
  - https://securelist.com/key-group-ransomware-samples-and-telegram-schemes/114025/
rules:
  - title: Disable Windows Defender Functionalities Via Registry Keys
    description: Detects when attackers or tools disable Windows Defender functionalities via the Windows registry
    platform: sigma
    severity: high
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

## Overview

Attackers or tools can disable Windows Defender functionalities by modifying specific registry keys. This behavior is documented in various security reports and technical documentation.

## Attack Chain

Adversaries manipulate specific registry subkeys within the Windows Defender policy or configuration paths to disable features such as real-time monitoring and Tamper Protection.

## Impact

Modification of these registry keys can result in the impairment of Windows Defender security features.

## Recommendation

Monitor for registry modification events targeting the keys specified in the detection rule and investigate unauthorized changes.
