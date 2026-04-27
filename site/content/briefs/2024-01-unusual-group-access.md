---
title: Unusual Group Name Accessed by User via Privileged Access Detection
slug: 2024-01-unusual-group-access
description: A machine learning job detected a user accessing an uncommon group name for privileged operations, potentially indicating privilege escalation or unauthorized account manipulation on a Windows system.
date: "2024-01-24T12:00:00Z"
severities:
  - low
tags:
  - privileged-access-detection
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/pad
  - https://attack.mitre.org/techniques/T1068/
  - https://attack.mitre.org/techniques/T1078/
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/007/
  - https://attack.mitre.org/techniques/T1069/
  - https://attack.mitre.org/tactics/TA0004/
  - https://attack.mitre.org/tactics/TA0007/
  - https://attack.mitre.org/tactics/TA0003/
rules:
  - title: Detect Account Added to Privileged Group via Net.exe
    description: Detects the use of net.exe to add a user to a highly privileged group like Domain Admins, Administrators, or Enterprise Admins, which can indicate privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - account_manipulation
      - privilege_escalation
    techniques:
      - T1068
      - T1098
      - T1098.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Account Added to Privileged Group via PowerShell
    description: Detects the use of PowerShell to add a user to a highly privileged group, which can indicate privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - account_manipulation
      - privilege_escalation
    techniques:
      - T1068
      - T1098
      - T1098.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the potential for privilege escalation attempts on Windows systems, detected by Elastic's Privileged Access Detection (PAD) integration. Specifically, a machine learning job identifies users accessing group names that are unusual for their typical behavior, especially those associated with elevated privileges. This activity, while potentially legitimate, can also signify malicious attempts to manipulate group memberships or escalate privileges. This detection relies…
