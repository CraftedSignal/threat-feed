---
brief_id: brief-2026-11-13-reg-exe-hive-dumping
event_id: brief-2026-11-13-reg-exe-hive-dumping
revision: 1
activity_at: "2026-11-13T14:02:38Z"
title: Windows Registry Hive Dumping via Reg.exe
slug: 2026-11-reg-exe-hive-dumping
description: The Windows utility reg.exe can be used to export sensitive registry hives such as SAM, SYSTEM, and SECURITY, a technique leveraged for credential access.
date: "2026-11-13T14:02:38Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.002
    technique_name: Security Account Manager
    evidence: Detects the usage of "reg.exe" in order to dump sensitive registry hives.
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
  - https://eqllib.readthedocs.io/en/latest/analytics/aed95fc6-5e3f-49dc-8b35-06508613f979.html
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003/T1003.md
  - https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md#atomic-test-1---registry-dump-of-sam-creds-and-secrets
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_reg_dumping_sensitive_hives.yml
rules:
  - title: Dumping of Sensitive Hives Via Reg.EXE
    description: Detects the usage of reg.exe to dump sensitive registry hives including SAM, SYSTEM, and SECURITY.
    platform: sigma
    severity: high
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

The Windows utility reg.exe is used to perform operations that can dump sensitive registry hives. By executing export or save operations targeting the HKLM\SAM, HKLM\SYSTEM, or HKLM\SECURITY keys, registry data can be extracted for offline analysis.

## Impact

Extraction of these registry hives allows an attacker to obtain local account password hashes (SAM) and system configuration secrets (SYSTEM), which can lead to account compromise.

## Recommendation

Monitor process creation logs for the execution of reg.exe with parameters associated with hive exportation. Investigate instances where reg.exe interacts with sensitive registry hives to determine if the activity is authorized.
