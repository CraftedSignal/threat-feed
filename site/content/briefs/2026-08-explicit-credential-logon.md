---
title: Detection of Suspicious Explicit Credential Local Logon
slug: 2026-08-explicit-credential-logon
description: Detection logic for monitoring Windows Event ID 4648 to identify potential privilege escalation through unauthorized explicit credential usage.
date: "2026-08-03T08:54:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - security-auditing
  - privilege-escalation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: It might indicate an attacker attempting to escalate privileges after obtaining credentials for a different user account.
    confidence_band: high
rules:
  - title: Potentially Suspicious Explicit Credential Local Logon
    description: Detects Windows Event ID 4648 (logon with explicit credentials) originating from non-system and non-Program Files paths, excluding processes using the current user's identity.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1134.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Identify processes executing Event ID 4648 from C:\Users\* or C:\ProgramData\*
      technique_id: T1134
      data_needed:
        - Windows Security Log Event 4648
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Event ID 4648 indicates explicit credential usage which can be abused for privilege escalation.
---

This brief details a detection engineering approach for identifying suspicious use of explicit credentials within a Windows environment. Windows Event ID 4648 is generated when a process attempts to log on to a local or remote resource using explicit credentials, such as when using the 'runas' command. While this is a legitimate administrative function, attackers frequently leverage this technique to escalate privileges or move laterally after harvesting credentials from memory or local configuration files. This rule specifically targets local logon attempts where the process executing the request originates from non-standard directories and does not match the current user context, effectively filtering out common system-managed or administrative activity to highlight potential abuse.

## Impact

Successful abuse of explicit credentials allows an attacker to bypass standard access controls, impersonate other users (including high-privilege service accounts or domain administrators), and maintain persistence within the target system. This technique is often a critical stage in the progression from initial access to full domain compromise.

## Recommendation

Deploy the provided Sigma rule to your SIEM environment to detect deviations from established administrative patterns.
- Enable Windows Security Auditing (specifically "Audit Logon" subcategory) to ensure Event ID 4648 is generated.
- Baseline common administrative tools used in the environment to tune the 'filter_main_*' selections and minimize false positives.
- Alert on occurrences that bypass current filters, as these represent high-interest activity for manual threat hunting.
