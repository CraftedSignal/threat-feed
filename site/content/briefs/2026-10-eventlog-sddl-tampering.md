---
title: Windows EventLog Security Descriptor Tampering
slug: 2026-10-eventlog-sddl-tampering
description: Attackers are modifying the 'CustomSD' registry value in Windows EventLog channels to restrict access to logs and blind security monitoring capabilities.
date: "2026-10-12T18:16:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - eventlog
  - registry
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.002
    technique_name: 'Impair Defenses: Disable or Modify System Firewall'
    evidence: The analytic detects suspicious modifications to the EventLog security descriptor registry value for defense evasion.
    confidence_band: high
rules:
  - title: Detect Modification of Windows EventLog CustomSD Registry Value
    description: Detects unauthorized modifications to the EventLog security descriptor (CustomSD) registry value, which is used to restrict access to logs for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
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
    - action: Deploy registry monitoring for CustomSD modifications.
      owner: Detection Engineering
      due: 48h
      evidence: Registry tampering identified as a key defense evasion technique.
  hunt_leads:
    - lead: Search for historical changes to CustomSD registry keys.
      technique_id: T1685.001
      data_needed:
        - Registry modification logs (Event ID 13)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Historical activity can indicate prior persistence or evasion attempts.
---

This threat concerns the abuse of the Windows EventLog architecture, specifically the modification of the 'CustomSD' registry value within 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\&lt;Channel>\'. By injecting a malicious Security Descriptor Definition Language (SDDL) string into this registry key, an actor can alter the access control list (ACL) of specific event log channels. This activity is a recognized method for defense evasion, often utilized by ransomware groups like LockBit to ensure their malicious actions remain unrecorded or to prevent security software from ingesting critical telemetry. Successful manipulation of these descriptors can effectively blind security operations centers (SOCs) by blocking legitimate user and system service access to log data. Because this is a legacy configuration option and rarely required for modern administrative tasks, any modification to these specific registry paths should be treated as highly suspicious.

## Attack Chain

1. Attacker gains administrative access to the targeted Windows host.
2. Attacker identifies a specific Windows EventLog channel (e.g., Security, System, or Application) to target for suppression.
3. Attacker uses native tools, such as 'reg.exe' or PowerShell, to interact with the Windows Registry.
4. Attacker navigates to 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\[ChannelName]'.
5. Attacker creates or modifies the 'CustomSD' value with a crafted SDDL string designed to strip permissions from local users or security services.
6. The Windows EventLog service applies the modified security descriptor, effectively restricting access.
7. Attacker proceeds with further malicious actions, such as deploying ransomware or exfiltrating data, without the activity being recorded in the tampered log channel.

## Impact

Successful exploitation results in the complete loss of visibility into the affected event log channel. By restricting access, attackers can hide indicators of compromise, prevent the ingestion of logs into SIEM or EDR platforms, and evade detection by automated security monitoring systems. This technique has been observed in campaigns associated with LockBit ransomware and is used to facilitate persistent unauthorized access and defense evasion.

## Recommendation

Prioritize the identification of unauthorized registry modifications to the 'CustomSD' value.
* Deploy the Sigma rule provided in this brief to monitor registry modifications within the EventLog service key.
* Configure endpoint logging (Sysmon Event ID 13) to capture all modifications to registry keys matching the path pattern 'HKLM\System\CurrentControlSet\Services\Eventlog\*\CustomSD'.
* Audit existing 'CustomSD' values in the environment to identify non-standard or unexpected security descriptors.
* Restrict administrative privileges to limit the ability of unauthorized users or processes to modify sensitive registry keys.
