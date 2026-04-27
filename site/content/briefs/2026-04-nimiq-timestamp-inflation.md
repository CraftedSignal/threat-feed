---
title: Nimiq Blockchain Timestamp Manipulation Vulnerability
slug: 2026-04-nimiq-timestamp-inflation
description: A vulnerability in nimiq-blockchain versions 1.3.0 and earlier allows malicious validators to manipulate block timestamps, leading to inflation of the monetary supply.
date: "2026-04-09T21:16:11Z"
severities:
  - high
tags:
  - blockchain
  - timestamp-manipulation
  - inflation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Credentials
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-40093
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40093
rules:
  - title: Detect Large Timestamp Discrepancies in Nimiq Blocks
    description: Detects blocks with timestamps significantly ahead of the current time, potentially indicating timestamp manipulation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - application
      - nimiq
  - title: Detect Unusual Reward Increases in Nimiq Blockchain
    description: Detects significant deviations from the expected block reward, potentially indicating monetary supply inflation.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - application
      - nimiq
rules_count: 2
---

Nimiq-blockchain, which provides persistent block storage for Nimiq's Rust implementation, is susceptible to a critical vulnerability. In versions 1.3.0 and earlier, the block timestamp validation lacks an upper bound check against the wall clock. This flaw enables a malicious block-producing validator to set block timestamps to an arbitrarily distant future. The vulnerability directly impacts reward calculations within the blockchain, specifically through `Policy::supply_at()` and…
