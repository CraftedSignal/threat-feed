---
title: Suspicious PowerShell Usage in Registry Run Keys
slug: 2026-09-suspicious-powershell-run-keys
description: Adversaries frequently employ PowerShell commands within Windows Registry Run keys to achieve persistence and facilitate stealthy execution upon system startup.
date: "2026-09-01T12:13:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: Adversaries use Registry Run keys to maintain access across reboots.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_powershell_in_run_keys.yml
  - https://github.com/frack113/atomic-red-team/blob/a9051c38de8a5320b31c7039efcbd3b56cf2d65a/atomics/T1547.001/T1547.001.md
rules:
  - title: Detect Suspicious PowerShell In Registry Run Keys
    description: Detects potential PowerShell commands or malicious code indicators within Windows registry run keys.
    platform: sigma
    severity: medium
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
    - action: Deploy Sigma rule to identify existing suspicious registry keys
      owner: Detection Engineering
      due: 48h
      evidence: Source rule provides baseline for detection
  hunt_leads:
    - lead: Search for non-standard registry run keys containing PowerShell keywords
      technique_id: T1547.001
      data_needed:
        - Registry set logs (Event ID 12, 13)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Registry modification logs can expose latent persistence
---

Persistence via Windows Registry Run keys is a common technique used by various malware families, including those associated with Malware-as-a-Service (MaaS) operations like SystemBC, to maintain access across reboots. Threat actors modify specific registry hives (Run, RunOnce, or Policy/Explorer/Run) to inject malicious PowerShell commands that execute in the background. By utilizing common PowerShell parameters like -w hidden, -nop, and ExecutionPolicy Bypass, attackers attempt to minimize user visibility and security tool interference. This technique effectively bypasses traditional startup folder monitoring and remains a persistent threat for organizations failing to audit registry modifications involving script execution. Defenders must monitor registry set events to identify unauthorized additions to these keys that invoke command-line interpreters.

## Attack Chain

1. Initial access is established through phishing, exploit, or credential compromise.
2. The attacker executes a staging command to set a persistent entry in the registry.
3. The attacker modifies HKLM or HKCU Run keys to include a malicious PowerShell one-liner.
4. The command utilizes obfuscation, such as Base64 encoding or hidden window styles.
5. On system reboot or user login, the Windows Registry Run key triggers the execution of powershell.exe.
6. The PowerShell process executes the payload, which may involve downloading additional stages via Invoke-WebRequest or Invoke-Expression.
7. The final payload achieves C2 connectivity or initiates ransomware/exfiltration activity.

## Impact

Successful persistence allows attackers to maintain long-term access to compromised hosts, facilitating ongoing data exfiltration, ransomware deployment, or lateral movement. Unchecked registry modifications can lead to system-wide compromises where legitimate administrative persistence mechanisms are subverted to run malicious code automatically on every boot.

## Recommendation

1. Deploy the Sigma rule below to detect suspicious modifications to Run keys that incorporate PowerShell execution artifacts.
2. Establish a baseline for legitimate administrative scripts that modify registry Run keys to reduce false positives.
3. Enable Sysmon or Windows Audit Policy for Registry modifications (Event ID 12, 13, 14) to capture the necessary telemetry.
4. Use the provided Atomic Red Team test cases (e.g., T1547.001) to validate the efficacy of existing detection coverage for registry persistence.
