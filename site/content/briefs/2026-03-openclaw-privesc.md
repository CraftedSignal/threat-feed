---
title: OpenClaw Privilege Escalation Vulnerability (CVE-2026-32922)
slug: 2026-03-openclaw-privesc
description: OpenClaw before 2026.3.11 is vulnerable to privilege escalation in the device.token.rotate function, allowing attackers with limited operator.pairing scope to mint tokens with elevated operator.admin privileges, potentially leading to remote code execution.
date: "2026-03-29T13:17:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - privilege-escalation
  - remote-code-execution
  - cve
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32922
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-4jpw-hj22-2xmc
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-unvalidated-scope-in-device-token-rotate
ioc_counts:
  email: 2
rules:
  - title: Detect OpenClaw Token Rotation Exploit Attempt
    description: Detects attempts to exploit CVE-2026-32922 by monitoring HTTP POST requests to the /device.token.rotate endpoint, potentially indicating unauthorized token minting.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1555.005
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw system.run execution
    description: Detects execution of system.run, which is used to run arbitrary code on connected nodes. This can be used as a follow-up to a successful exploit of CVE-2026-32922
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.11 are susceptible to a critical privilege escalation vulnerability identified as CVE-2026-32922. This flaw resides within the `device.token.rotate` function. Attackers who have already gained `operator.pairing` scope can exploit this vulnerability to mint new tokens with broader, unauthorized scopes, due to a failure in the application to properly constrain the newly minted scopes. This allows attackers to elevate their privileges to `operator.admin` on paired…
