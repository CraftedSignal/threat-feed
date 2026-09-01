---
title: Service Registry Permission Weakness Enumeration
slug: 2026-09-service-registry-hijacking
description: Adversaries perform reconnaissance on Windows service registry keys using PowerShell to identify weak permissions susceptible to service hijacking and privilege escalation.
date: "2026-09-01T12:18:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1574.011/T1574.011.md#atomic-test-1---service-registry-permissions-weakness
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.4
rules:
  - title: Detect Service Registry ACL Enumeration via PowerShell
    description: Detects the use of Get-Acl to enumerate security permissions on Windows service registry keys, a common reconnaissance step for service hijacking.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1574.011
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to capture registry ACL reconnaissance.
      owner: Detection Engineering
      due: 48h
      evidence: Rule mapping to T1574.011
  hunt_leads:
    - lead: Search logs for Get-Acl executions targeting the Services registry hive.
      technique_id: T1574.011
      data_needed:
        - PowerShell Script Block logs (Event 4104)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Enumeration is a precursor to registry modification.
  mitigation_plan:
    - priority: medium_term
      action: Review and harden ACLs on service registry keys to remove non-admin write access.
      owner: IT Operations
      addresses: T1574.011
      evidence: Source identifies registry permissions as the root cause of this vector.
---

Adversaries often attempt to gain persistence or elevate privileges by hijacking the configuration of Windows services. By exploiting weak Access Control Lists (ACLs) on service registry keys located at HKLM\SYSTEM\CurrentControlSet\Services, an attacker can modify the 'ImagePath' parameter to point to a malicious binary or script. When the service starts or restarts, the system executes the attacker-controlled code, often with SYSTEM or local service-level privileges. To identify these vulnerable targets, attackers use PowerShell commands, specifically Get-Acl, to enumerate the security descriptors of these registry keys. Defenders should monitor for reconnaissance activity that targets these specific service registry paths, as it often precedes an attempt to modify them for lateral movement or persistence.

## Attack Chain

1. Attacker establishes initial access on a Windows endpoint.
2. Attacker executes PowerShell scripts to enumerate service registry configurations.
3. Attacker uses the Get-Acl cmdlet targeting HKLM\SYSTEM\CurrentControlSet\Services to identify weak registry permissions.
4. Attacker identifies a service registry key where the 'Authenticated Users' or local user group has write/modify access.
5. Attacker modifies the 'ImagePath' registry value within the vulnerable key to point to a malicious payload.
6. Attacker triggers a service restart or waits for a system reboot to execute the malicious binary.
7. Malicious code executes in the context of the service, resulting in privilege escalation or persistent access.

## Impact

Successful exploitation allows attackers to execute arbitrary code with elevated privileges, potentially resulting in full system compromise, exfiltration of sensitive data, or the installation of persistent backdoors within the organization's infrastructure.

## Recommendation

- Deploy the provided Sigma rule to detect PowerShell-based enumeration of service registry ACLs.
- Enable PowerShell Script Block Logging (Event ID 4104) to ensure visibility into the commands executed by potential attackers.
- Audit registry permissions on HKLM\SYSTEM\CurrentControlSet\Services to ensure that standard users do not have write or modify access to service configuration keys.
- Implement monitoring for modifications to the ImagePath registry value within the Services hive.
