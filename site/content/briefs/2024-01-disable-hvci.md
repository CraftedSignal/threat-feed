---
title: Windows HVCI Disabled via Registry Modification
slug: 2024-01-disable-hvci
description: Detection of Hypervisor-protected Code Integrity (HVCI) being disabled by modifying specific Windows registry keys, potentially allowing the execution of malicious kernel-mode code.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
cves:
  - id: CVE-2022-21894
    cvss: 4.4
    epss: 0.40934
references:
  - https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/
rules:
  - title: Detect HVCI Disable via Registry
    description: Detects disabling of Hypervisor-protected Code Integrity (HVCI) by monitoring changes in the Windows registry.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect HVCI Disable via Registry - Process
    description: Detects processes that modify the HVCI-related registry key
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the disabling of Hypervisor-protected Code Integrity (HVCI) on Windows systems. HVCI is a critical security feature that protects the kernel and system processes from tampering by malicious code. Attackers may disable HVCI to bypass security controls and execute unsigned kernel-mode code, leading to kernel-level rootkits or other severe security breaches. This activity is detected by monitoring changes to specific Windows registry keys related to HVCI configuration using Sysmon Event ID 13. The activity is associated with the BlackLotus Campaign, which exploits CVE-2022-21894.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., via phishing or exploiting a vulnerability).
2.  The attacker escalates privileges to gain administrative access, required to modify system-level registry settings.
3.  The attacker uses a script or executable to modify the registry.
4.  The script modifies the registry key `HKLM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled` to a value of `0x00000000`.
5.  The system restarts, and HVCI is disabled.
6.  The attacker deploys and executes unsigned kernel-mode code or a rootkit.
7.  The malicious code gains persistent control of the system at the kernel level.
8.  The attacker performs further malicious activities, such as data theft or system compromise.

## Impact

Successful disabling of HVCI can lead to a complete compromise of the affected system. Attackers can install kernel-level rootkits, bypass security controls, and execute arbitrary code in the kernel. This can lead to data theft, system instability, and further propagation of malware within the network. The BlackLotus campaign exploits this type of vulnerability to establish persistent, low-level control over compromised systems.

## Recommendation

*   Enable Sysmon Event ID 13 logging to capture registry modification events.
*   Deploy the Sigma rule `Detect HVCI Disable via Registry` to your SIEM to detect HVCI being disabled.
*   Investigate any detected instances of HVCI being disabled, as this can be a sign of malicious activity.
*   Ensure systems are patched against CVE-2022-21894 to prevent exploitation.
*   Monitor for suspicious processes modifying the registry keys related to HVCI.
*   Tune the Sigma rule `Detect HVCI Disable via Registry` to filter out legitimate administrative scripts, if necessary.
