---
title: Detection of Registry Keys Used for Persistence
slug: 2026-07-registry-persistence
description: This brief outlines a detection strategy for identifying modifications to Windows registry keys commonly used for persistence, including Run, Winlogon, and Image File Execution Options, enabling detection engineers to alert on unauthorized system startup entries for malicious code execution to prevent persistent access.
date: "2026-07-24T09:03:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - registry
  - windows
  - endpoint
  - malware
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The analytic identifies modifications to registry keys commonly used for persistence mechanisms. It leverages data from endpoint detection sources like Sysmon or Carbon Black, focusing on specific registry paths known to initiate applications or services during system startup.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/registry_keys_used_for_persistence.yml
rules:
  - title: Detect Registry Key Modifications for Persistence
    description: Detects modifications to Windows registry keys commonly used for establishing and maintaining persistence, including Run, Winlogon, and Image File Execution Options.
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
---

This intelligence describes a detection capability designed to identify modifications to critical Windows registry keys frequently leveraged by threat actors for establishing and maintaining persistence on compromised systems. The detection monitors registry paths such as those associated with `RunOnce`, `StartupApproved\Run`, various `Shell Folders`, `Winlogon` entries, `Appinit_Dlls`, `Image File Execution Options`, and others known to automatically launch applications or services upon system startup or user logon. Unauthorized changes to these keys are a strong indicator of malicious activity, as they allow attackers to achieve persistent access, execute arbitrary code, or maintain control over compromised systems even after reboots, posing a severe threat to system integrity and security. This detection is crucial for identifying backdoor installations, malware loaders, and other forms of persistent access.

## Impact

Successful modification of these registry keys by an attacker directly leads to persistent access on the compromised system. This means malicious code can execute automatically each time the system boots or a user logs in, granting the attacker a persistent foothold regardless of session or system restarts. The impact includes sustained control over the infected machine, potential for lateral movement, data exfiltration, or the deployment of further destructive payloads like ransomware. Organizations failing to detect and remediate such persistence mechanisms risk prolonged compromise and severe operational disruption, potentially leading to significant financial losses and reputational damage.

## Recommendation

* Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect suspicious registry modifications.
* Enable Sysmon process-creation and registry logging (specifically Event ID 13 for `RegistryEvent (Value Set)`) to activate the rules above.
* Monitor for changes to the specific registry paths listed in the Sigma rule's `TargetObject` selection, as these are critical for system startup and persistence.
* Implement host-based intrusion prevention systems (HIPS) to block unauthorized modifications to sensitive registry keys mentioned in the `detection` section.
* Regularly review logs related to registry modifications for endpoints identified in `registry_keys_used_for_persistence` to identify and triage potential persistence attempts.
