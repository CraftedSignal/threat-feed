---
title: ShrinkLocker Ransomware BitLocker Registry Tampering
slug: 2026-08-shrinklocker-bitlocker-tampering
description: The ShrinkLocker ransomware actor exploits native Windows registry configurations to manipulate BitLocker encryption behavior, bypassing security requirements to facilitate unauthorized data encryption.
date: "2026-08-17T18:37:23Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - ShrinkLocker
tags:
  - ransomware
  - defense-evasion
  - registry-tampering
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The malware ShrinkLocker alters various registry keys to change how BitLocker handles encryption, potentially bypassing TPM requirements
    confidence_band: high
references:
  - https://www.bleepingcomputer.com/news/security/new-shrinklocker-ransomware-uses-bitlocker-to-encrypt-your-files/
rules:
  - title: Detect BitLocker Registry Policy Tampering
    description: Detects suspicious modification of BitLocker registry keys often used by ransomware to bypass TPM or enforce encryption requirements
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1112
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
    - action: Deploy the BitLocker registry monitoring Sigma rule
      owner: Detection Engineering
      due: 48h
      evidence: Source explicitly identifies registry keys targeted by ShrinkLocker
  mitigation_plan:
    - priority: immediate
      action: Review Group Policy configurations for BitLocker to ensure they cannot be overridden by standard user-level processes
      owner: IT Operations
      addresses: T1112
      evidence: Source identifies registry tampering as the primary vector for ransomware
---

ShrinkLocker is a ransomware strain that abuses the native BitLocker Drive Encryption (BDE) functionality to lock victim systems. Rather than relying solely on external encryption tools, the malware manipulates Windows Registry keys under `HKLM\Software\Policies\Microsoft\FVE\` to reconfigure how the operating system handles disk encryption. By programmatically modifying these policies, ShrinkLocker can bypass TPM requirements, force the creation of partial encryption keys, or enforce specific PIN-based startup configurations. This approach allows the actor to weaponize built-in system security features against the host, effectively locking the system and demanding a ransom. Defenders must monitor for unauthorized modifications to these sensitive security registry paths to detect early-stage tampering before the encryption process completes.

## Attack Chain

1. The malware gains initial access to the Windows host through a spearphishing attachment or drive-by download.
2. The process elevates privileges to administrative levels to perform system-wide registry modifications.
3. The malware queries the `HKLM\Software\Policies\Microsoft\FVE\` registry path to check current encryption policies.
4. The process executes registry writes to set `EnableBDEWithNoTPM` or `EnableNonTPM` to `1`, lowering the barrier for BitLocker deployment.
5. The malware further enforces configurations by setting values such as `UsePIN` or `UseTPMPIN` to `2` to dictate the encryption unlocking mechanism.
6. ShrinkLocker triggers the built-in `manage-bde.exe` utility or the underlying BitLocker API to initiate disk encryption using the newly applied policy constraints.
7. The system is rebooted or encryption finishes, resulting in a locked machine requiring the attacker-defined key or PIN to access files.

## Impact

Successful deployment of ShrinkLocker leads to the complete encryption of enterprise data via native Windows features. This technique causes significant operational downtime, as it prevents legitimate system access and renders local data inaccessible without the actor-controlled key. The ransomware has been observed targeting various Windows environments, and the nature of the encryption makes recovery difficult without established backups or the specific keys generated during the tampering process.

## Recommendation

1. Deploy the Sigma rules below to monitor for unauthorized modifications to BitLocker registry keys; focus on any process (other than authorized management tools) attempting to set `FVE` policy values.
2. Implement registry auditing (Sysmon Event ID 13) specifically for the `HKLM\Software\Policies\Microsoft\FVE\` registry tree.
3. Restrict administrative rights to ensure only authorized IT management software can modify system-wide encryption policies.
4. Monitor for the execution of `manage-bde.exe` by processes not associated with standard system administration tasks.
