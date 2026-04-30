---
title: CVE-2026-26183 Windows RPC API Local Privilege Escalation
slug: 2026-04-windows-rpc-privesc
description: CVE-2026-26183 allows a locally authenticated attacker to escalate privileges due to improper access control within the Windows RPC API.
date: "2026-04-14T18:26:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - rpc
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26183
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26183
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26183
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Potential Exploitation of CVE-2026-26183 via Suspicious Process Creation
    description: Detects suspicious process creations by low-privileged users that might be related to the exploitation of CVE-2026-26183. This rule looks for unusual processes being spawned by standard users which could indicate privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Malicious RPC Client
    description: Detects potential malicious RPC client activity based on unusual process execution.  This is a heuristic and should be tuned for the environment.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-26183 is a vulnerability in the Windows RPC API that enables a local attacker with existing authorized access to elevate their privileges. This improper access control issue poses a significant risk as it allows a malicious actor to gain higher-level permissions on a compromised system. The vulnerability, reported on April 14, 2026, affects the Windows operating system. An attacker could potentially leverage this vulnerability to perform actions such as installing software, modifying data, or creating new accounts with full user rights, ultimately gaining complete control over the affected system. Microsoft has released a patch to address this vulnerability, and immediate patching is strongly recommended.

## Attack Chain

1.  The attacker gains initial access to the system with limited privileges via legitimate means, such as compromised credentials.
2.  The attacker identifies the presence of CVE-2026-26183 in the Windows RPC API.
3.  The attacker crafts a malicious RPC request designed to exploit the improper access control.
4.  The attacker executes the crafted RPC request, targeting a vulnerable function within the Windows RPC API.
5.  Due to the lack of proper access control checks, the RPC API processes the request with elevated privileges.
6.  The attacker uses the elevated privileges to modify system configurations, install malicious software, or create new accounts with administrator rights.
7.  The attacker escalates their privileges from a limited user to a system administrator.
8.  The attacker now has full control of the system and can perform any desired actions.

## Impact

A successful exploitation of CVE-2026-26183 can lead to complete system compromise. A local attacker can escalate their privileges to the highest level, allowing them to perform any action on the system. This could result in data theft, installation of malware, or denial of service. Given the widespread use of Windows, a successful exploit could affect a large number of systems if left unpatched.

## Recommendation

*   Apply the security update released by Microsoft to patch CVE-2026-26183 on all affected Windows systems immediately. Refer to the Microsoft advisory [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26183].
*   Implement the provided Sigma rule to detect suspicious process creation events that might indicate exploitation attempts.
*   Monitor system logs for unusual RPC activity, especially originating from low-privileged accounts, and correlate with other suspicious events to identify potential exploitation.
