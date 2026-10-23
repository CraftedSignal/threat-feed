---
brief_id: brief-2026-10-23-linux-vm-fingerprinting
event_id: brief-2026-10-23-linux-vm-fingerprinting
revision: 1
activity_at: "2026-10-23T14:38:55Z"
title: 'Linux: Unauthorized Virtual Machine Fingerprinting'
slug: 2026-10-linux-vm-fingerprinting
description: Non-root users querying specific system hardware files to identify virtualized environments for reconnaissance or sandbox evasion.
date: "2026-10-23T14:38:55Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - discovery
  - defense-evasion
  - linux
  - reconnaissance
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: An adversary may attempt to get detailed information about the operating system and hardware.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1497
    technique_name: Virtualization/Sandbox Evasion
    evidence: This rule identifies common locations used to discover virtual machine hardware by a non-root user.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/discovery_virtual_machine_fingerprinting.toml
  - https://attack.mitre.org/techniques/T1082/
  - https://attack.mitre.org/techniques/T1497/001/
rules:
  - title: Detect Non-Root VM Fingerprinting via Hardware Files
    description: Detects non-root users querying specific DMI or hardware information files commonly used for VM identification
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - discovery
    techniques:
      - T1082
      - T1497.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify non-root processes accessing hardware enumeration files
      technique_id: T1082
      data_needed:
        - Process creation logs with full command line and user context
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: This rule identifies common locations used to discover virtual machine hardware by a non-root user.
---

Adversaries often perform VM fingerprinting to tailor malicious activity or evade sandbox detection. This activity involves non-root users accessing specific Linux system files to enumerate virtual hardware identifiers. This technique has been observed in the wild by threat actors utilizing the Pupy RAT.

## Impact

Successful VM fingerprinting allows adversaries to detect virtualized environments, enabling them to alter their execution path to avoid detection by automated analysis systems or to tailor their payload to the specific target environment.

## Recommendation

* Implement process monitoring on Linux endpoints to detect non-root processes querying hardware configuration files in /sys and /proc directories.
* Review the process execution lineage of any alert to confirm if the activity aligns with legitimate administrative or inventory tooling.
* Configure an allowlist for known-good management agents or monitoring utilities that legitimately query system hardware.
* Ensure endpoint logging (Auditd, Elastic Defend, or equivalent) captures process arguments to differentiate between unauthorized reconnaissance and system-level inventory.
