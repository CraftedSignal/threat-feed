---
brief_id: brief-2026-11-11-pass-the-hash
event_id: brief-2026-11-11-pass-the-hash
revision: 1
activity_at: "2026-11-11T07:32:20Z"
title: Pass the Hash Lateral Movement Detection
slug: 2026-11-pass-the-hash
description: This detection identifies Pass the Hash (PtH) activity via Windows Security Event Logs by monitoring for specific logon types and processes associated with NTLM authentication.
date: "2026-11-11T07:32:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - lateral-movement
  - windows
  - pth
references:
  - https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events
  - https://web.archive.org/web/20170909091934/https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis
  - https://web.archive.org/web/20201001165303/https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/account_management/win_security_pass_the_hash_2.yml
rules:
  - title: Detect Pass the Hash Activity via Logon Events
    description: Detects the attack technique pass the hash which is used to move laterally inside the network.
    platform: sigma
    severity: medium
    tactics:
      - lateral-movement
    techniques:
      - T1550.002
    data_sources:
      - windows
      - security
rules_count: 1
---

Pass the Hash is an attack technique used to move laterally inside a network. The successful use of PtH for lateral movement between workstations triggers Windows Security Event ID 4624.

## Detection Logic
The detection monitors for Event ID 4624 with specific logon types and processes.
- Logons where LogonType is 3, LogonProcessName is 'NtLmSsp', and KeyLength is 0 (excluding 'ANONYMOUS LOGON').
- Logons where LogonType is 9 and LogonProcessName is 'seclogo'.
