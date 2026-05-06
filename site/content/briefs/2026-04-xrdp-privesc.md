---
title: xrdp Privilege Escalation Vulnerability (CVE-2026-32107)
slug: 2026-04-xrdp-privesc
description: xrdp versions through 0.10.5 are vulnerable to a privilege escalation flaw (CVE-2026-32107) where improper privilege management during the privilege drop process could allow an authenticated local attacker to escalate privileges to root and execute arbitrary code.
date: "2026-04-17T20:16:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xrdp
  - privilege-escalation
  - cve-2026-32107
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-32107
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32107
  - https://github.com/neutrinolabs/xrdp/releases/tag/v0.10.6
  - https://github.com/neutrinolabs/xrdp/security/advisories/GHSA-p5m6-7m43-pjv9
rules:
  - title: Suspicious Process Execution from xrdp Session
    description: Detects suspicious processes spawned from an xrdp session, potentially indicating exploitation of CVE-2026-32107.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Elevated Privileges Execution from xrdp
    description: Detects execution of commands with elevated privileges (sudo, su) from xrdp session.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-32107 affects xrdp, an open-source Remote Desktop Protocol (RDP) server. Specifically, versions up to and including 0.10.5 contain a flaw in the session execution component. The vulnerability stems from the improper handling of errors during the privilege drop process. This allows a local, authenticated attacker to potentially escalate their privileges to root. Successful exploitation requires an additional, unspecified exploit to trigger the vulnerable code path. The vulnerability has been addressed in xrdp version 0.10.6. Defenders should prioritize upgrading affected systems to version 0.10.6 or later. The reported CVSS v3.1 base score is 8.8, indicating a high severity. This vulnerability allows local attackers to execute arbitrary code with elevated privileges.

## Attack Chain

1. An attacker gains local access to a system running a vulnerable version of xrdp (<= 0.10.5) with valid user credentials.
2. The attacker initiates an xrdp session, triggering the vulnerable session execution component.
3. The xrdp session attempts to drop privileges as part of its normal operation.
4. An error occurs during the privilege drop process due to the flaw described in CVE-2026-32107.
5. Due to the improper error handling, the privilege drop fails, or partially fails, leaving the process with elevated privileges.
6. The attacker exploits this partially dropped or retained privilege context. This step requires a currently unspecified, additional exploit.
7. The attacker executes arbitrary code with root privileges due to the incomplete privilege drop.
8. The attacker persists or pivots to other systems based on their elevated access.

## Impact

Successful exploitation of CVE-2026-32107 allows a local attacker to gain root privileges on a vulnerable system. This can lead to complete system compromise, including data theft, modification, or destruction. While the vulnerability requires an additional exploit to be fully realized, the high CVSS score reflects the significant impact of a successful attack. The number of potential victims is dependent on the prevalence of vulnerable xrdp versions within an organization's infrastructure.

## Recommendation

*   Upgrade xrdp to version 0.10.6 or later to remediate CVE-2026-32107, as per the GitHub release notes ([https://github.com/neutrinolabs/xrdp/releases/tag/v0.10.6](https://github.com/neutrinolabs/xrdp/releases/tag/v0.10.6)).
*   Monitor systems running xrdp for unexpected privilege escalation attempts or suspicious process behavior.
* Consider deploying the provided Sigma rule to detect suspicious process creation events related to xrdp exploitation.
