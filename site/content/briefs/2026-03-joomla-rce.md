---
title: Joomla com_mb24sysapi Module Unauthenticated RCE (CVE-2026-32968)
slug: 2026-03-joomla-rce
description: An unauthenticated remote attacker can exploit an OS command injection vulnerability (CVE-2026-32968) in the com_mb24sysapi module of Joomla, leading to remote code execution and full system compromise.
date: "2026-03-23T12:16:08Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-32968
  - joomla
  - rce
  - command-injection
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: OS Command Injection
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32968
  - https://certvde.com/de/advisories/VDE-2026-024
  - https://certvde.com/de/advisories/VDE-2026-025
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect Joomla com_mb24sysapi Command Injection Attempt
    description: Detects attempts to exploit command injection vulnerability in the Joomla com_mb24sysapi module by looking for suspicious parameters in HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Joomla com_mb24sysapi POST Command Injection Attempt
    description: Detects attempts to exploit command injection vulnerability in the Joomla com_mb24sysapi module via POST requests by looking for suspicious parameters in HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-32968 describes a critical remote code execution (RCE) vulnerability affecting the com_mb24sysapi module in Joomla. The vulnerability stems from improper neutralization of special elements within OS commands, allowing an unauthenticated remote attacker to inject arbitrary commands. Successful exploitation of this vulnerability can lead to complete compromise of the affected system. This vulnerability is identified as a variant of CVE-2020-10383, suggesting a similar underlying flaw…
