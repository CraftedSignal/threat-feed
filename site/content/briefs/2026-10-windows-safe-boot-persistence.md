---
title: Windows Registry Modification for Safe Mode Persistence
slug: 2026-10-windows-safe-boot-persistence
description: Adversaries modify SafeBoot registry keys to ensure malicious drivers or services execute during Safe Mode, enabling persistence and bypassing standard startup security.
date: "2026-10-12T18:20:31Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Adversaries can use them to persist drivers or services in Safe Mode.
    confidence_band: high
rules:
  - title: Detect SafeBoot Registry Key Modification
    description: Detects modifications to the Windows SafeBoot registry keys which could indicate an attempt to achieve persistence in Safe Mode.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
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
    - action: Deploy Sigma rule to monitor HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot registry keys.
      owner: Detection Engineering
      due: 48h
      evidence: Registry modification for Safe Mode persistence is a known TTP.
  hunt_leads:
    - lead: Search for any recent modifications to SafeBoot keys in registry audit logs.
      technique_id: T1547.001
      data_needed:
        - Sysmon Event ID 13
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Registry changes to these specific paths are rare and highly suspicious.
---

Threat actors utilize modifications to Windows SafeBoot registry keys, specifically within the "Minimal" and "Network" subkeys, to maintain persistence on compromised systems. By injecting entries into these paths, attackers ensure that malicious drivers or services are authorized to execute even when the operating system is booted in Safe Mode. This technique is particularly effective at evading security solutions that rely on standard startup configurations or drivers that may be disabled during normal operation but remain active in Safe Mode. The "Network" key is specifically targeted to allow persistence while maintaining network connectivity for C2 communication. This behavior has been observed in ransomware operations where persistent access is required to facilitate full system encryption.

## Attack Chain

1. Attacker gains administrative privileges on the target Windows system.
2. Attacker prepares a malicious driver or service binary to be executed.
3. Attacker identifies the appropriate registry subkey under HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal or Network.
4. Attacker modifies the registry to add a new service or driver entry referencing the malicious binary.
5. Attacker forces a system reboot into Safe Mode.
6. The Windows kernel initializes, reads the modified SafeBoot keys, and loads the attacker-controlled binary.
7. The malicious code executes in the context of the boot process or during service initialization.
8. Attacker achieves persistent command and control or data encryption capabilities despite security software restrictions.

## Impact

Successful exploitation allows attackers to maintain persistence through reboots and circumvent traditional endpoint security controls that may not be fully initialized or active during Safe Mode. This facilitates long-term access, potential for lateral movement, and the execution of destructive actions like ransomware deployment. Observed activity has historically been linked to ransomware groups seeking to ensure their malicious payloads survive system hardening or recovery attempts.

## Recommendation

1. Deploy the provided Sigma rule to detect modifications to the SafeBoot registry hives.
2. Implement strict access control lists (ACLs) on the HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot registry keys to prevent unauthorized write operations.
3. Monitor endpoint registry activity using Sysmon Event ID 13 specifically targeting the SafeBoot paths.
4. Audit installed drivers and services regularly to identify unsigned or suspicious binaries registered to load during system boot.
