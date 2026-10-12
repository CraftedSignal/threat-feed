---
title: Impairment of Windows Event Logging via AutoLogger Registry Manipulation
slug: 2026-10-windows-autologger-impairment
description: Adversaries manipulate Windows WMI AutoLogger registry keys to disable logging providers and telemetry, facilitating defense evasion and persistence on compromised systems.
date: "2026-10-12T18:08:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - registry
  - etw
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The analytic detects the disabling of an AutoLogger session or one of its providers, by identifying changes to the Registry values 'Start' and 'Enabled'.
    confidence_band: high
references:
  - https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session
rules:
  - title: Detect Windows AutoLogger Disabling via Registry Modification
    description: Detects the disabling of Windows WMI AutoLogger sessions or providers by identifying registry modifications to 'Start' or 'Enabled' values set to '0'.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy registry monitoring Sigma rule to production SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for registry monitoring.
  hunt_leads:
    - lead: Search for historical registry modifications to \WMI\Autologger\ paths.
      technique_id: T1562.001
      data_needed:
        - Endpoint registry logs (Sysmon EID 13)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Technique is frequently used in post-compromise defense evasion.
  mitigation_plan:
    - priority: medium_term
      action: Review Group Policy and configuration management baseline for WMI AutoLogger settings.
      owner: IT Operations
      addresses: T1562.001
      evidence: Registry keys control system diagnostic logging.
---

Adversaries frequently employ defense evasion techniques to blind security tooling and EDR solutions. A specific, high-impact method involves the modification of Windows WMI AutoLogger configurations. By altering registry keys located under "\WMI\Autologger\", specifically targeting the "Start" or "Enabled" values by setting them to "0x00000000", an attacker can effectively disable event tracing providers. This action suppresses the generation of logs that would otherwise capture malicious activity, such as process execution, lateral movement, or unauthorized credential access. This technique has been observed in various campaigns, including IcedID and LazyScripter, as a mechanism to maintain long-term stealth on compromised endpoints. Defenders must monitor registry modification events to detect attempts to tamper with these core security and diagnostic controls.

## Impact

Successful exploitation of this technique blinds security operations centers by preventing the recording of attacker actions within the Windows Event Log subsystem. This concealment allows adversaries to maintain persistence, conduct further reconnaissance, and exfiltrate data without triggering common behavioral detection logic. It is particularly dangerous in environments that rely heavily on native ETW-based telemetry for visibility.

## Recommendation

Detection engineering teams should monitor registry modifications targeting WMI AutoLogger paths and values.

- Deploy the provided Sigma rule to identify modifications where the "Start" or "Enabled" values under "WMI\Autologger\" keys are set to zero.
- Enable Sysmon Event ID 13 (RegistryValue-Set) logging across all endpoints to ensure visibility into these modifications.
- Perform environment-specific tuning to exclude legitimate administrative activity or automated configuration management software that might periodically audit or reset these keys.
- Monitor for instances where this registry change occurs in conjunction with other suspicious activities, such as disabling Windows Defender or unauthorized process execution.
