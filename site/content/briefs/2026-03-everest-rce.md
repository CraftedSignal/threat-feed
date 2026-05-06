---
title: EVerest EV Charging Stack Remote Code Execution via Stack Buffer Overflow (CVE-2026-22790)
slug: 2026-03-everest-rce
description: EVerest versions before 2026.02.0 are vulnerable to a stack-based buffer overflow (CVE-2026-22790) in the `HomeplugMessage::setup_payload` function, enabling remote code execution via network frames with oversized SLAC payloads.
date: "2026-03-26T15:16:31Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - everest
  - rce
  - buffer-overflow
  - cve-2026-22790
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22790
  - https://github.com/EVerest/EVerest/security/advisories/GHSA-wh8w-7cfc-gq7m
rules:
  - title: Detect Large SLAC Payloads to EVerest
    description: Detects network connections with unusually large payloads potentially targeting the EVerest stack buffer overflow.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - network_connection
      - linux
  - title: Detect memcpy near HomeplugMessage::setup_payload (Generic)
    description: Detects process execution that contains memcpy near HomeplugMessage::setup_payload. This is a generic detection to assist in further investigation of the memcpy exploitation.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

EVerest is an open-source software stack designed for managing EV charging infrastructure. Prior to version 2026.02.0, a critical vulnerability exists within the `HomeplugMessage::setup_payload` function. Specifically, the code trusts the `len` parameter after an `assert` statement during the processing of SLAC (Signal Level Attenuation Characterization) payloads. In release builds, the `assert` check is removed, which allows an attacker to send network frames with oversized SLAC payloads. This…
