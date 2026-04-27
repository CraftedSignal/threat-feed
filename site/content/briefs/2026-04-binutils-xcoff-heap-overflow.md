---
title: Binutils XCOFF Heap-Based Buffer Overflow Vulnerability (CVE-2026-6846)
slug: 2026-04-binutils-xcoff-heap-overflow
description: A heap-buffer-overflow vulnerability exists in binutils when processing a specially crafted XCOFF object file, potentially leading to arbitrary code execution or denial of service.
date: "2026-04-22T09:16:27Z"
severities:
  - high
tags:
  - binutils
  - heap-buffer-overflow
  - CVE-2026-6846
  - xcoff
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-6846
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6846
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Binutils Invocation
    description: Detects suspicious invocations of binutils tools that might indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1053
    data_sources:
      - process_creation
      - linux
  - title: Detect Unusual File Access by Binutils
    description: Detects unusual file access patterns by binutils processes, which might indicate the processing of malicious files.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1053
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-6846 describes a heap-based buffer overflow vulnerability found in the binutils suite of programs. The vulnerability occurs when processing a maliciously crafted XCOFF (Extended Common Object File Format) object file during the linking process. An attacker with local access could potentially exploit this flaw by enticing a user to process a malicious XCOFF file. Successful exploitation could lead to arbitrary code execution with the privileges of the user running binutils, unauthorized…
