---
title: Windows WalletService Use-After-Free Privilege Escalation (CVE-2026-32080)
slug: 2026-04-walletservice-uaf
description: CVE-2026-32080 is a use-after-free vulnerability in the Windows WalletService, allowing a locally authorized attacker to elevate privileges.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: email
    value: '[email&#160;protected]'
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

CVE-2026-32080 is a use-after-free vulnerability affecting the Windows WalletService. This vulnerability allows an attacker with local access and low privileges to elevate their privileges to SYSTEM. The WalletService is a component of the Windows operating system responsible for managing user credentials and payment information. A successful exploit could allow an attacker to perform actions with elevated permissions, potentially leading to system compromise. The vulnerability was disclosed on April 14, 2026, and is documented in the Microsoft Security Response Center update guide. Exploitation requires specific conditions to be met within the WalletService's memory management, making it a complex but critical vulnerability.

## Attack Chain

1.  Attacker gains initial access to the target system with low privileges.
2.  Attacker identifies that the target system is running a vulnerable version of Windows WalletService.
3.  Attacker crafts a specific input to trigger the use-after-free condition within WalletService.
4.  The malicious input causes the WalletService to free a memory region.
5.  The attacker then reallocates the same memory region with attacker-controlled data.
6.  WalletService attempts to access the previously freed memory, now containing attacker-controlled data.
7.  This leads to the execution of arbitrary code in the context of the WalletService process, which runs with elevated privileges.
8.  The attacker leverages this code execution to escalate their privileges to SYSTEM.

## Impact

Successful exploitation of CVE-2026-32080 allows a local attacker to elevate privileges to SYSTEM. This could lead to complete system compromise, including unauthorized data access, modification, and deletion. The vulnerability affects systems running the Windows WalletService, which is present on most Windows installations. This poses a significant risk to environments where local users are not fully trusted, such as shared workstations or servers. The impact is high due to the potential for complete system takeover.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-32080 (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32080).
*   Monitor process creation events for unusual activity originating from the WalletService process to detect potential exploitation attempts. Use the Sigma rule `Detect Suspicious WalletService Process Creation`.
*   Monitor network connections for unusual outbound connections originating from WalletService using the Sigma rule `Detect WalletService Outbound Network Connection`.
*   Investigate any instances of WalletService crashing or exhibiting abnormal behavior.
