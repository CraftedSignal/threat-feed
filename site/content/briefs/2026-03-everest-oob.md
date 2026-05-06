---
title: EVerest Out-of-Bounds Access Vulnerability (CVE-2026-26008)
slug: 2026-03-everest-oob
description: EVerest, an EV charging software stack, has an out-of-bounds access vulnerability in versions prior to 2026.02.0, which can lead to remote crash or memory corruption when the CSMS sends UpdateAllowedEnergyTransferModes over the network.
date: "2026-03-27T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - ev-charging
  - out-of-bounds
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26008
  - https://github.com/EVerest/EVerest/security/advisories/GHSA-vw95-6jj7-3fv9
rules:
  - title: Detect Suspicious UpdateAllowedEnergyTransferModes Messages
    description: Detects potentially malicious UpdateAllowedEnergyTransferModes messages sent to EVerest instances.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
  - title: EVerest Process Crash
    description: Detects potential EVerest process crashes based on system logs.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - system
      - linux
rules_count: 2
---

EVerest is an EV charging software stack used for managing electric vehicle charging infrastructure. Versions prior to 2026.02.0 are vulnerable to an out-of-bounds access issue (CVE-2026-26008) that can be triggered remotely. The vulnerability stems from how the Central System Management System (CSMS) handles the `UpdateAllowedEnergyTransferModes` message over the network. Successful exploitation can lead to a crash of the EVerest software or memory corruption, potentially disrupting EV…
