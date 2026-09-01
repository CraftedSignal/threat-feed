---
title: Modification of Outlook Security Registry Settings
slug: 2026-09-outlook-security-registry
description: Detects unauthorized modifications to Microsoft Outlook security-related registry keys that may be used to weaken email protections or establish persistence.
date: "2026-09-01T13:09:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - windows
  - registry
  - outlook
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
    evidence: Detects changes to the registry values related to outlook security settings
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy registry monitoring for Outlook security keys
      owner: Detection Engineering
      due: 72h
      evidence: Source provides specific registry paths for monitoring
  mitigation_plan:
    - priority: medium_term
      action: Restrict user-level permissions to modify HKEY_CURRENT_USER registry keys
      owner: IT Operations
      addresses: Persistence and security setting tampering
      evidence: Microsoft documentation on Outlook security
  gaps:
    - Visibility into registry modifications if EDR/Sysmon is not deployed on endpoints
---

This threat brief focuses on detecting unauthorized changes to Microsoft Outlook security settings via the Windows Registry. Attackers often target the `\Outlook\Security\` registry path to lower security configurations, such as allowing blocked attachments or disabling macro warnings, which facilitates the execution of malicious payloads. While legitimate administrative changes occur, security teams should monitor for registry modifications made by processes other than the official Outlook executable (`OUTLOOK.EXE`). This technique is associated with persistence mechanisms where attackers leverage Outlook features to run malicious code upon application startup. Monitoring these registry keys is a critical component for identifying attempts to subvert Microsoft Office application security.

## Impact

Successful manipulation of these registry settings can lead to the bypassing of security restrictions on file attachments and macros, facilitating the delivery and execution of malware, ransomware, or persistence mechanisms within the host environment.

## Recommendation

Deploy the Sigma rule provided in this brief to detect non-standard processes modifying Outlook security registry keys. Tune the rule to exclude legitimate software deployment or configuration management agents. Focus investigation on any registry changes occurring from processes residing in user-writable directories or temporary locations.

## Rules

- title: "Detect Modification of Outlook Security Registry Settings"
 description: "Detects unauthorized changes to Outlook security registry settings by processes other than Outlook.exe"
 logsource:
 category: "registry_set"
 product: "windows"
 detection:
 selection:
 TargetObject|contains|all:
 - "\\SOFTWARE\\Microsoft\\Office\\"
 - "\\Outlook\\Security\\"
 filter:
 Image|startswith:
 - "C:\\Program Files\\Microsoft Office\\"
 - "C:\\Program Files (x86)\\Microsoft Office\\"
 Image|endswith: "\\OUTLOOK.EXE"
 condition: "selection and not filter"
 level: "medium"
 tags:
 - "attack.persistence"
 - "attack.t1137"
 tests:
 positive:
 - name: "Registry key modified by unauthorized process"
 data:
 - TargetObject: "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Security\\Level1Remove"
 Image: "C:\\Users\\Public\\malware.exe"
 negative:
 - name: "Legitimate modification by Outlook"
 data:
 - TargetObject: "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Security\\Level1Remove"
 Image: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
 falsepositives:
 - "Legitimate administrative activity or security software configuration changes"
 handoff:
 detection_confidence: "medium"
 required_telemetry:
 - log_source: "Sysmon registry_set"
 event_or_channel: "Event ID 12 or 13"
 required_fields:
 - "TargetObject"
 - "Image"
 availability: "available"
 notes: "Requires Sysmon or EDR logging for registry modifications"
 validation:
 status: "test_defined"
 steps:
 - "Use Atomic Red Team test T1137 to modify an Outlook registry key"
 expected_telemetry: "Event 12/13 with TargetObject matching the path and Image matching the test process"
 pass_criteria: "Rule triggers for non-Outlook image paths"
 atomic_reference: "bfe6ac15-c50b-4c4f-a186-0fc6b8ba936c"
