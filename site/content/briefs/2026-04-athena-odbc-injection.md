---
title: Amazon Athena ODBC Driver Command Injection Vulnerability (CVE-2026-35558)
slug: 2026-04-athena-odbc-injection
description: A command injection vulnerability (CVE-2026-35558) exists in the Amazon Athena ODBC driver before 2.1.0.0 due to improper neutralization of special elements in connection parameters, potentially leading to arbitrary code execution or authentication redirection.
date: "2026-04-03T21:17:11Z"
severities:
  - high
tags:
  - command injection
  - cve-2026-35558
  - athena
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35558
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35558
  - https://aws.amazon.com/security/security-bulletins/2026-013-aws/
  - https://docs.aws.amazon.com/athena/latest/ug/odbc-v2-driver-release-notes.html
rules:
  - title: Detect Suspicious Process Creation from Athena ODBC Driver (Windows)
    description: Detects suspicious process creation events where the parent process is the Amazon Athena ODBC driver executable, potentially indicating command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Athena ODBC Driver Network Connection
    description: Detects suspicious network connections initiated by the Amazon Athena ODBC driver executable to unusual destinations, potentially indicating command and control activity after successful command injection.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Amazon Athena ODBC driver versions prior to 2.1.0.0 are susceptible to a command injection vulnerability, identified as CVE-2026-35558. This flaw arises from the driver's failure to properly neutralize special elements within connection parameters during the authentication process. A remote attacker could exploit this vulnerability by crafting malicious connection strings that, when processed by the vulnerable driver, allow for the execution of arbitrary code on the system or redirection of…
