---
title: Apache MINA Arbitrary Code Execution Vulnerability
slug: 2026-04-apache-mina-rce
description: A critical arbitrary code execution vulnerability (CVE-2026-41635) exists in Apache MINA versions 2.0.0 through 2.0.27, 2.1.0 through 2.1.10, and 2.2.0 through 2.2.5 due to missing class validation in the AbstractIoBuffer.resolveClass() method, potentially allowing attackers to execute arbitrary code on applications using Apache MINA.
date: "2026-04-27T16:09:56Z"
severities:
  - critical
tags:
  - apache-mina
  - rce
  - deserialization
  - cve-2026-41635
vendors:
  - Apache
products:
  - MINA 2.0
  - MINA 2.1
  - MINA 2.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-41635
    cvss: 9.8
references:
  - https://ccb.belgium.be/advisories/warning-critical-arbitrary-code-execution-vulnerability-apache-mina-patch-immediately
  - https://lists.apache.org/thread/1l91w1mqsb3lwfd504fs045ylxntt2tm
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41635
rules:
  - title: Detect Apache MINA Vulnerable Class Deserialization Attempt
    description: Detects potential exploitation attempts of CVE-2026-41635 based on suspicious class names being deserialized in network traffic.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Process Creation by Java
    description: Detects processes spawned by Java that are commonly associated with exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical arbitrary code execution vulnerability, CVE-2026-41635, has been identified in Apache MINA, an open-source network application framework. The vulnerability affects versions 2.0.0 through 2.0.27, 2.1.0 through 2.1.10, and 2.2.0 through 2.2.5. The flaw lies within the AbstractIoBuffer.resolveClass() method, where a branch lacks class validation, bypassing the classname allowlist. This allows remote attackers with low privileges to execute arbitrary code on systems using Apache MINA…
