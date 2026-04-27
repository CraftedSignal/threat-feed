---
title: Git for Windows NTLM Hash Leak Vulnerability (CVE-2026-32631)
slug: 2026-04-git-ntlm-hash-leak
description: Git for Windows versions prior to 2.53.0.windows.3 are vulnerable to NTLM hash theft by attackers who can trick users into cloning malicious repositories or checking out malicious branches, leading to potential credential compromise.
date: "2026-04-15T18:17:17Z"
severities:
  - medium
tags:
  - cve
  - credential-access
  - windows
  - git
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1187
    technique_name: Forced Authentication
cves:
  - id: CVE-2026-32631
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32631
rules:
  - title: Detect Git Process Spawning Cmd with /c net use
    description: Detects Git process spawning cmd.exe to execute net use command, which can be an indicator of NTLM authentication attempt
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1187
    data_sources:
      - process_creation
      - windows
  - title: Detect Git Network Connection to Uncommon Ports
    description: Detects Git process making network connections to uncommon ports, indicating potential malicious repository access
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Git for Windows versions before 2.53.0.windows.3 are susceptible to a vulnerability (CVE-2026-32631) that exposes users' NTLM hashes to malicious actors. This occurs when a user interacts with a specially crafted Git repository or branch hosted on an attacker-controlled server. The vulnerability stems from the lack of sufficient protections against unauthorized NTLM authentication requests during Git operations. The attack doesn't require user interaction beyond the initial clone or checkout…
