---
title: Registry Manipulation via WMI Stdregprov for Evasion
slug: 2026-07-registry-manipulation-wmi-stdregprov
description: Attackers are leveraging `wmic.exe` to modify the Windows registry through the WMI `StdRegProv` class, specifically using methods like `CreateKey` and `SetStringValue`, to evade detection and bypass traditional security monitoring focused on `reg.exe` or `regedit.exe`.
date: "2026-07-03T14:56:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - registry-modification
  - defense-evasion
  - wmi
  - windows
  - process-creation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: Detects the usage of wmic.exe to modify Windows registry via the WMI StdRegProv class write methods (CreateKey, DeleteKey, SetStringValue, etc.).
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Detects the usage of wmic.exe to modify Windows registry via the WMI StdRegProv class write methods (CreateKey, DeleteKey, SetStringValue, etc.).
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Attackers specifically choose this technique to evade detection and bypass security monitoring focused on traditional registry modification commands.
    confidence_band: high
references:
  - https://www.bitdefender.com/en-us/blog/businessinsights/shrinklocker-decryptor-from-friend-to-foe-and-back-again
  - https://trustedsec.com/blog/command-line-underdog-wmic-in-action
  - https://trustedsec.com/blog/wmi-for-script-kiddies
  - https://learn.microsoft.com/en-us/previous-versions/windows/desktop/regprov/stdregprov
rules:
  - title: Registry Manipulation via WMI Stdregprov
    description: Detects the usage of wmic.exe to modify Windows registry via the WMI StdRegProv class write methods (CreateKey, DeleteKey, SetStringValue, etc.), indicating potential defense evasion or persistence.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - persistence
    techniques:
      - T1047
      - T1112
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Attackers are increasingly utilizing `wmic.exe` in conjunction with the Windows Management Instrumentation (WMI) `StdRegProv` class to perform registry modifications, a technique observed to be employed by groups such as ShrinkLocker. This method allows threat actors to execute operations such as creating, deleting, or setting registry values (e.g., `CreateKey`, `DeleteKey`, `SetStringValue`) in an unconventional manner. By employing WMI for registry manipulation, attackers aim to bypass security monitoring tools that primarily focus on detecting changes made via standard utilities like `reg.exe` or `regedit.exe`. This technique serves as a defense evasion tactic, making it more challenging for defenders to identify and respond to malicious registry changes, which can be critical for achieving persistence or altering system configurations.

## Impact

The primary impact of this technique is successful defense evasion, allowing attackers to establish persistence or modify system behavior without triggering traditional registry monitoring alerts. While the direct functional damage depends on the specific registry keys modified, the use of `wmic.exe` for such operations indicates an attacker's intent to operate stealthily within an environment. If this technique goes undetected, it can enable long-term compromise, installation of malware, or complete system takeover by allowing malicious entries to be written to critical registry locations. The specific scale of victimization or targeted sectors are not detailed in this technical brief, but the underlying capability affects any Windows environment where WMI is available.

## Recommendation

*   Deploy the Sigma rule "Registry Manipulation via WMI Stdregprov" to your SIEM and tune for your environment.
*   Ensure Sysmon process creation logging is enabled to capture `wmic.exe` executions with full command-line details.
*   Investigate any `wmic.exe` process creations that include `stdregprov` and registry modification methods (`CreateKey`, `SetStringValue`, etc.) in their command line.
