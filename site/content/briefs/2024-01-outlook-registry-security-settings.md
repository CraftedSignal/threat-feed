---
title: Outlook Security Settings Registry Modification
slug: 2024-01-outlook-registry-security-settings
description: Attackers modify Outlook security settings via registry changes to enable malicious mail rules and bypass security controls, potentially leading to persistence and data compromise.
date: "2024-01-03T18:15:00Z"
severities:
  - medium
tags:
  - persistence
  - registry_modification
  - outlook
  - email
vendors:
  - Microsoft
products:
  - Microsoft Outlook
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1137/T1137.md
  - https://learn.microsoft.com/en-us/outlook/troubleshoot/security/information-about-email-security-settings
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_office_outlook_security_settings.yml
rules:
  - title: Outlook Security Settings Modification via Process
    description: Detects changes to Outlook security settings in the registry made by suspicious processes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Modifying Outlook Security Registry Keys
    description: This rule detects suspicious processes modifying Outlook security-related registry keys, indicating potential attempts to weaken security controls.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers are known to modify Outlook security settings by directly manipulating registry values. This tactic allows them to bypass built-in security controls and enable potentially malicious functionalities such as running unsafe mail client rules. This circumvention of security measures can be leveraged for various malicious purposes, including persistence, data exfiltration, and further compromise of the victim's system. The specific registry keys targeted reside under…
