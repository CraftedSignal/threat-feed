---
title: Base64 Decoder 1.1.2 Stack-Based Buffer Overflow (CVE-2019-25634)
slug: 2026-03-base64-decoder-overflow
description: Base64 Decoder 1.1.2 is vulnerable to a stack-based buffer overflow (CVE-2019-25634) allowing local attackers to achieve arbitrary code execution via a crafted input file that triggers an SEH overwrite.
date: "2026-03-24T12:16:04Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2019-25634
  - buffer-overflow
  - seh-overwrite
  - code-execution
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25634
  - http://4mhz.de/b64dec.html
  - http://4mhz.de/download.php?file=b64dec-1-1-2.zip
  - https://www.exploit-db.com/exploits/46625
  - https://www.vulncheck.com/advisories/base64-decoder-local-buffer-overflow-seh-egghunter
rules:
  - title: Detect SEH Overwrite Attempt
    description: Detects attempts to overwrite the Structured Exception Handler (SEH) chain, a common technique used in buffer overflow exploits.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Base64 Decoder 1.1.2 Execution with Suspicious Arguments
    description: Detects execution of Base64 Decoder 1.1.2 with unusually long or suspicious arguments, potentially indicative of an overflow attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Base64 Decoder version 1.1.2 is susceptible to a stack-based buffer overflow vulnerability, identified as CVE-2019-25634. This flaw enables a local attacker to execute arbitrary code on a vulnerable system. The vulnerability arises from insufficient bounds checking when processing input, allowing an attacker to overwrite critical parts of the stack. Successful exploitation requires the attacker to craft a malicious input file specifically designed to trigger the overflow. The impact of this…
