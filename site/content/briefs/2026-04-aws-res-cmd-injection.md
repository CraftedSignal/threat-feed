---
title: AWS Research and Engineering Studio OS Command Injection Vulnerability (CVE-2026-5707)
slug: 2026-04-aws-res-cmd-injection
description: A remote authenticated attacker can execute arbitrary commands as root on the virtual desktop host by crafting a malicious session name in AWS Research and Engineering Studio (RES) versions 2025.03 through 2025.12.01 due to unsanitized input, leading to complete system compromise.
date: "2026-04-06T22:16:25Z"
severities:
  - critical
tags:
  - cve
  - command-injection
  - aws
  - res
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Services
cves:
  - id: CVE-2026-5707
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5707
  - https://aws.amazon.com/security/security-bulletins/2026-014-aws/
  - https://github.com/aws/res/issues/151
  - https://github.com/aws/res/releases/tag/2026.03
rules:
  - title: Detect Suspicious Session Names with OS Command Injection Characters
    description: Detects suspicious session names containing characters commonly used in OS command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Root Command Execution via Malicious Session Name
    description: Detects execution of common root commands initiated through exploitation of the session name vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-5707 is an OS command injection vulnerability affecting AWS Research and Engineering Studio (RES) versions 2025.03 through 2025.12.01. The vulnerability resides in the virtual desktop session name handling, where user-supplied input is not properly sanitized before being used in an OS command. A remote, authenticated attacker can exploit this flaw by providing a specially crafted session name, leading to arbitrary command execution as root on the virtual desktop host. Successful…
