---
title: Dell PowerProtect Data Domain Command Injection Vulnerability (CVE-2026-23778)
slug: 2026-04-dell-powerprotect-cmd-injection
description: A command injection vulnerability in Dell PowerProtect Data Domain (CVE-2026-23778) could allow a remote, high-privileged attacker to gain root-level access.
date: "2026-04-17T09:16:05Z"
severities:
  - critical
tags:
  - cve-2026-23778
  - command-injection
  - dell
  - powerprotect
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-23778
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23778
  - https://www.dell.com/support/kbdoc/en-us/000450699/dsa-2026-060-security-update-for-dell-powerprotect-data-domain-multiple-vulnerabilities
ioc_counts:
  url: 1
rules:
  - title: Detect Web Requests to Dell PowerProtect Systems
    description: Detects HTTP requests to Dell PowerProtect systems, which can be used to detect exploitation attempts.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Command Injection Attempts in Web Requests
    description: Detects common command injection attempts within HTTP requests, which could indicate exploitation of CVE-2026-23778.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-23778 is a command injection vulnerability affecting Dell PowerProtect Data Domain appliances running Data Domain Operating System (DD OS). The affected versions include Feature Release versions 7.7.1.0 through 8.5, LTS2025 release version 8.3.1.0 through 8.3.1.20, and LTS2024 release versions 7.13.1.0 through 7.13.1.50. A remote attacker with high privileges could exploit this vulnerability to execute arbitrary commands with root privileges on the affected system. Successful…
