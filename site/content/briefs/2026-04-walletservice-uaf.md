---
title: Windows WalletService Use-After-Free Privilege Escalation (CVE-2026-32080)
slug: 2026-04-walletservice-uaf
description: CVE-2026-32080 is a use-after-free vulnerability in the Windows WalletService, allowing a locally authorized attacker to elevate privileges.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - use-after-free
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32080
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32080
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32080
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious WalletService Process Creation
    description: Detects suspicious process creation events originating from the WalletService process, which could indicate exploitation of CVE-2026-32080.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect WalletService Outbound Network Connection
    description: Detects outbound network connections from the WalletService, which may indicate code execution and command and control activity after exploiting CVE-2026-32080.
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

CVE-2026-32080 is a use-after-free vulnerability affecting the Windows WalletService. This vulnerability allows an attacker with local access and low privileges to elevate their privileges to SYSTEM. The WalletService is a component of the Windows operating system responsible for managing user credentials and payment information. A successful exploit could allow an attacker to perform actions with elevated permissions, potentially leading to system compromise. The vulnerability was disclosed on…
