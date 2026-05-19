---
title: 'CVE-2026-45585: Windows BitLocker Security Feature Bypass Vulnerability (''YellowKey'')'
slug: 2026-05-yellowkey-bitlocker-bypass
description: CVE-2026-45585 is a security feature bypass vulnerability in Windows BitLocker, known as 'YellowKey', for which a public proof of concept exists, prompting Microsoft to release mitigation guidance prior to a security update.
date: "2026-05-19T23:29:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - bitlocker
  - security feature bypass
vendors:
  - Microsoft
products:
  - BitLocker
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45585
  - CVE-2026-45585
rules:
  - title: Detect Potential BitLocker Bypass via Modified Boot Configuration Data
    description: Detects CVE-2026-45585 exploitation — monitors changes to the Boot Configuration Data (BCD) that could indicate an attempt to bypass BitLocker.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Potential BitLocker Bypass via Volume Shadow Copy Deletion
    description: Detects CVE-2026-45585 exploitation —  detects attempts to delete volume shadow copies, which can be done to prevent recovery after a BitLocker bypass.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1485
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Microsoft is aware of a security feature bypass vulnerability in Windows BitLocker, publicly referred to as "YellowKey" (CVE-2026-45585). A proof of concept (PoC) for this vulnerability has been made public, potentially increasing the risk of exploitation. This bypass could allow unauthorized access to BitLocker-protected data. Microsoft is issuing this CVE and providing mitigation guidance to help organizations protect against this vulnerability until a security update is available. The specific details of the vulnerability and the mitigation steps are documented in the Microsoft Security Response Center (MSRC) advisory.

## Attack Chain

Given that the specifics of the vulnerability are not detailed in the source and only a PoC is mentioned, the following attack chain is inferred based on common BitLocker bypass techniques:

1.  Attacker gains physical access to a system with BitLocker enabled.
2.  Attacker modifies the boot process to inject malicious code or a custom bootloader (details depend on the specific bypass technique).
3.  The modified bootloader intercepts the BitLocker key during the pre-boot authentication process.
4.  The intercepted key is then used to decrypt the BitLocker-protected drive.
5.  Attacker gains access to the decrypted operating system and data.
6.  Attacker exfiltrates sensitive information or installs persistent backdoors.

## Impact

Successful exploitation of CVE-2026-45585 leads to a security feature bypass, allowing unauthorized access to BitLocker-protected data. This could result in the compromise of sensitive information, intellectual property theft, and potential reputational damage. The impact is significant, especially for organizations that rely on BitLocker for data-at-rest encryption and physical security. The lack of specific victim numbers or sectors targeted information prevents further detailing of the impact, but organizations using BitLocker should consider this a high-priority vulnerability.

## Recommendation

*   Review and implement the mitigation guidance provided by Microsoft in the MSRC advisory for CVE-2026-45585 to reduce the attack surface.
*   Monitor systems for unauthorized modifications to the boot process, referencing the attack chain described above, using process_creation logs and file_event logs to identify unusual activity.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts in your environment and tune them for your specific configuration.
