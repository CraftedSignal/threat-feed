---
title: Suspicious Service Installation for Defense Evasion
slug: 2026-07-suspicious-service-installation
description: Attackers are installing suspicious services, specifically NalDrv or PROCEXP152, via registry modifications to non-system32 folders to facilitate defense evasion by tools like Ghost-In-The-Logs, aiming to disable or impair security monitoring capabilities.
date: "2026-07-03T14:32:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - persistence
  - kernel-driver
  - windows
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_susp_service_installed.yml
  - https://web.archive.org/web/20200419024230/https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/
  - https://github.com/bats3c/Ghost-In-The-Logs
  - https://github.com/hfiref0x/KDU
rules:
  - title: Suspicious Service Installed
    description: Detects installation of NalDrv or PROCEXP152 services via registry-keys to non-system32 folders, indicating potential defense evasion using tools like Ghost-In-The-Logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

This threat brief outlines the installation of suspicious services, specifically "NalDrv" or "PROCEXP152", which are known to be used by defense evasion tools like Ghost-In-The-Logs. Ghost-In-The-Logs, often leveraging the Kernel Driver Utility (KDU) framework, aims to impair security monitoring by operating at a low level to evade detection by tools like Sysmon and Windows Event Logging. This activity typically involves modifying specific registry keys to point service binaries to non-system32 directories, a common tactic to hide malicious components. While a specific threat actor is not identified, this technique is broadly applicable to adversaries seeking to maintain stealth and persistence post-initial compromise, potentially impacting organizations across all sectors that rely on endpoint detection for security monitoring. The technique has been documented since at least 2019 and continues to be relevant for sophisticated adversaries.

## Attack Chain

1.  An attacker gains initial access to a Windows system through an unspecified mechanism.
2.  The attacker executes KDU or a similar tool to load a vulnerable or malicious kernel driver.
3.  The kernel driver modifies Windows registry keys associated with services.
4.  Specifically, `HKLM\System\CurrentControlSet\Services\NalDrv\ImagePath` or `HKLM\System\CurrentControlSet\Services\PROCEXP152\ImagePath` is modified.
5.  The `ImagePath` value is set to point to a malicious or repurposed driver located in a non-system32 folder.
6.  This enables the Ghost-In-The-Logs tool to run with elevated privileges and evade monitoring by Sysmon and Windows Event Logging.

## Impact

Successful exploitation allows an attacker to operate with significantly reduced visibility for defenders, as critical security logs from Sysmon and Windows Event Logging can be impaired or disabled. This defense evasion facilitates further malicious activity, such as data exfiltration, lateral movement, or the deployment of ransomware, without triggering alerts. The primary impact is the loss of detection and forensic capabilities, making incident response significantly more challenging and increasing the likelihood of a successful breach going undetected for extended periods. While specific victim counts are not available, any organization relying on endpoint visibility for threat detection is vulnerable to this technique.

## Recommendation

*   Deploy the Sigma rule "Suspicious Service Installed" to your SIEM to detect attempts to install these services outside of standard paths.
*   Ensure robust logging, especially Sysmon process creation, registry modification, and driver load events, is enabled and forwarded to your SIEM to provide the necessary data for the "registry_set" logsource category.
*   Regularly review your Sysmon configuration to ensure it covers suspicious registry modifications and driver installations, as highlighted in the `TargetObject` field of the rule.
*   Perform regular integrity checks on critical system directories and registry keys to identify unauthorized modifications, specifically monitoring changes to `HKLM\System\CurrentControlSet\Services` as referenced in the `TargetObject` field.
