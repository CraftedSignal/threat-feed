---
title: EVerest CAN Interface Stack Buffer Overflow Vulnerability (CVE-2026-23995)
slug: 2026-03-everest-can-overflow
description: A stack-based buffer overflow vulnerability exists in EVerest EV charging software stack versions prior to 2026.02.0. Passing an interface name longer than 16 characters to CAN open routines overflows `ifreq.ifr_name`, potentially leading to code execution.
date: "2026-03-27T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - everest
  - buffer-overflow
  - cve-2026-23995
  - ev-charging
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23995
  - https://github.com/EVerest/EVerest/security/advisories/GHSA-p47c-2jpr-mpwx
rules:
  - title: Detect Suspicious CAN Interface Names
    description: Detects potentially malicious CAN interface names in system configurations that exceed the allowed length.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - file_event
      - linux
  - title: Detect Everest Process Crash due to Signal 11
    description: Detects potential Everest process crashes related to the buffer overflow by monitoring for signal 11 (SIGSEGV).
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

EVerest is an open-source software stack for electric vehicle (EV) charging infrastructure. A stack-based buffer overflow vulnerability, tracked as CVE-2026-23995, affects versions prior to 2026.02.0. The vulnerability stems from improper handling of CAN (Controller Area Network) interface names during initialization. Specifically, when an interface name exceeding IFNAMSIZ (16 bytes) is supplied to CAN open routines, the `ifreq.ifr_name` buffer overflows, potentially corrupting adjacent stack…
