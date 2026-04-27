---
title: Amazon Athena ODBC Driver OS Command Injection Vulnerability (CVE-2026-5485)
slug: 2026-04-athena-odbc-cmd-injection
description: A critical OS command injection vulnerability (CVE-2026-5485) in the Amazon Athena ODBC driver before 2.0.5.1 for Linux allows local attackers to execute arbitrary code via specially crafted connection parameters.
date: "2026-04-04T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-5485
  - command injection
  - athena
  - odbc
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5485
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5485
  - https://aws.amazon.com/security/security-bulletins/2026-013-aws/
  - https://docs.aws.amazon.com/athena/latest/ug/odbc-v2-driver-release-notes.html
rules:
  - title: Detect Suspicious Athena ODBC Driver Process Creation
    description: Detects potential command injection attempts via suspicious command line arguments used with the Athena ODBC driver on Linux.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1203
    data_sources:
      - process_creation
      - linux
  - title: Detect Athena ODBC Driver Loading From Unusual Location
    description: Detects the Athena ODBC driver loading from a location outside the standard installation path.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1574.002
    data_sources:
      - image_load
      - linux
rules_count: 2
---

CVE-2026-5485 is an OS command injection vulnerability affecting the Amazon Athena ODBC driver before version 2.0.5.1 on Linux systems. The vulnerability resides in the browser-based authentication component of the driver. A local attacker can exploit this flaw by crafting malicious connection parameters that are then processed by the driver during a locally initiated connection attempt. Successful exploitation allows the attacker to execute arbitrary commands on the underlying system with the…
