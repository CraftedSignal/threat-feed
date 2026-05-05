---
title: Windows Defender Tracing Level Modification
slug: 2024-01-03-defender-tracing-level-modification
description: The following analytic detects modifications to the Windows registry specifically targeting the 'WppTracingLevel' setting within Windows Defender, potentially impairing its diagnostic capabilities and allowing attackers to evade detection.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - registry-modification
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Detect Windows Defender WppTracingLevel Registry Modification via Sysmon
    description: Detects modifications to the Windows Defender WppTracingLevel registry key.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
  - title: Detect Windows Defender WppTracingLevel Modification via PowerShell
    description: Detects modifications to the Windows Defender WppTracingLevel registry key using PowerShell.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to disable or modify Windows Defender's tracing level to evade detection. The "WppTracingLevel" setting within the Windows Defender registry can be modified to impair its diagnostic capabilities, effectively hiding malicious activities. This allows attackers to operate with reduced scrutiny and maintain persistence within the environment. Defenders should monitor for unauthorized changes to this registry key to detect potential attempts to impair Windows Defender's functionality. The technique is described in a Twitter post from December 2023.

## Attack Chain

1. An attacker gains initial access to the system, potentially through phishing or exploiting a vulnerability.
2. The attacker escalates privileges to obtain the necessary permissions to modify the registry.
3. The attacker uses a tool like `reg.exe` or PowerShell to modify the `WppTracingLevel` registry value.
4. The attacker sets the `WppTracingLevel` value to `0x00000001`, effectively reducing the tracing level.
5. Windows Defender's diagnostic capabilities are impaired due to the reduced tracing level.
6. The attacker performs malicious activities, such as deploying malware or exfiltrating data, with a reduced risk of detection.
7. The attacker attempts to maintain persistence by establishing footholds in the system.

## Impact

Successful modification of the Windows Defender tracing level can significantly impair the system's ability to detect and respond to threats. This can lead to a successful breach, data exfiltration, and long-term persistence of the attacker within the environment. While the exact number of victims is unknown, the potential impact is high due to the widespread use of Windows Defender.

## Recommendation

*   Enable Sysmon Event ID 13 logging to monitor registry modifications and activate the rules below.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect changes to the `WppTracingLevel` registry setting.
*   Investigate any detected modifications to the `WppTracingLevel` registry key.
