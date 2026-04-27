---
title: osslsigncode Stack Buffer Overflow Vulnerability (CVE-2026-39853)
slug: 2026-04-osslsigncode-overflow
description: A stack buffer overflow vulnerability (CVE-2026-39853) exists in osslsigncode versions prior to 2.12 due to insufficient validation of digest length during PKCS#7 signature verification, potentially leading to arbitrary code execution.
date: "2026-04-09T16:16:31Z"
severities:
  - high
tags:
  - osslsigncode
  - buffer-overflow
  - authenticode
  - code-signing
  - CVE-2026-39853
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-39853
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39853
rules:
  - title: Detect osslsigncode Verify Command Execution
    description: Detects execution of the osslsigncode verify command, which is a prerequisite for exploiting CVE-2026-39853.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - linux
  - title: Detect Crash Related to osslsigncode
    description: Detects a crash or fault event where osslsigncode is the primary process.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A stack buffer overflow vulnerability has been identified in osslsigncode, a tool used for Authenticode signing and timestamping. Specifically, versions prior to 2.12 are susceptible to CVE-2026-39853. The vulnerability occurs during the verification of PKCS#7 signatures in PE, MSI, CAB, and script files. The code copies the digest value from a parsed SpcIndirectDataContent structure into a fixed-size stack buffer (64 bytes) without proper length validation. This allows an attacker to craft a…
