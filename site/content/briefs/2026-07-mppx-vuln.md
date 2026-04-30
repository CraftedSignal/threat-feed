---
title: MPPX TypeScript Interface Vulnerability (CVE-2026-34209)
slug: 2026-07-mppx-vuln
description: A vulnerability exists in mppx TypeScript interface before version 0.4.11, allowing attackers to close or grief channels for free by submitting close vouchers equal to the settled amount due to incorrect validation.
date: "2026-03-31T15:21:06Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - vulnerability
  - payment-channel
  - typescript
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-34209
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34209
ioc_counts:
  email: 2
rules:
  - title: Detect Mismatched Close Voucher Amounts
    description: Detects close voucher submissions where the voucher amount equals the settled amount, potentially indicating exploitation of CVE-2026-34209.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - application
      - mppx
rules_count: 1
---

The mppx library is a TypeScript interface designed for machine payments protocols. A vulnerability, identified as CVE-2026-34209, exists in versions prior to 0.4.11. Specifically, the `tempo/session` cooperative close handler incorrectly validates close voucher amounts. Instead of using a less than or equal to (`<=`) comparison, it uses a less than (`<`) comparison when checking against the on-chain settled amount. This flaw allows a malicious actor to submit a close voucher with an amount…
