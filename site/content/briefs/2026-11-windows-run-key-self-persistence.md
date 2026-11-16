---
brief_id: brief-2026-11-16-windows-run-key-self-persistence
event_id: brief-2026-11-16-windows-run-key-self-persistence
revision: 1
activity_at: "2026-11-16T21:28:38Z"
title: Windows Run Key Self-Registration from User-Writable Paths
slug: 2026-11-windows-run-key-self-persistence
description: Malware, including ClickFix-style loaders and NodeJS-based payloads, frequently achieves persistence by dropping binaries into user-writable directories and registering them within the Windows Run registry key.
date: "2026-11-16T21:28:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic defined based on provided Splunk query.
tags:
  - persistence
  - windows
  - clickfix
  - endpoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    subtechnique_id: T1547.001
    subtechnique_name: Registry Run Keys / Startup Folder
    evidence: Malware commonly drops its payload into the user profile and then adds itself to the Run key to survive reboots.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1547/001/
  - https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_run_key_self_registration_from_user_writable_path.yml
rules:
  - title: Detect Windows Run Key Self-Registration from User-Writable Path
    description: Detects a binary executing from a user-writable path (C:\Users, C:\ProgramData, or C:\PerfLogs) that adds its own path to the 'CurrentVersion\Run' registry key for persistence.
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
    - action: Deploy the provided Sigma detection rule to your SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for identifying persistent malware behavior.
  hunt_leads:
    - lead: Identify processes originating from C:\Users\, C:\ProgramData\, or C:\PerfLogs\ that have modified Run registry keys.
      technique_id: T1547.001
      data_needed:
        - Sysmon Event ID 13
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The source identifies this as a primary indicator for self-registering persistent malware.
  mitigation_plan:
    - priority: short_term
      action: Audit and restrict user write permissions on sensitive directories where executable code is not expected.
      owner: IT Operations
      addresses: T1547.001
---

## Overview

Threat actors leverage the Windows Registry to maintain persistence across system reboots. A common technique involves dropping malicious payloads into user-writable directories, such as C:\Users, C:\ProgramData, or C:\PerfLogs, and subsequently creating entries in the 'CurrentVersion\Run' registry key. This behavior is notably associated with 'ClickFix' style attacks, where social engineering leads users to execute remote MSI installations or NodeJS-based loaders, which then configure themselves to launch automatically upon user login.

## Impact

Successful exploitation of this technique allows an attacker to maintain persistent, unauthorized access to an endpoint, ensuring malicious code executes during every user session.

## Recommendation

1. Deploy endpoint monitoring for Registry value set events (Sysmon Event ID 13).
2. Filter known legitimate software that registers in the Run key from user-writable directories to reduce noise.
3. Investigate instances where processes executing from non-standard locations (User/ProgramData/PerfLogs) modify Run registry keys, as these are rarely authorized for standard application behavior.
4. Use the hunt leads provided to baseline your environment's authorized persistence mechanisms.
