---
title: CVE-2026-32150 Function Discovery Service Race Condition Privilege Escalation
slug: 2024-01-23-fdwsd-privesc
description: CVE-2026-32150 describes a race condition vulnerability in the Function Discovery Service (fdwsd.dll) that allows a locally authorized attacker to elevate privileges on a Windows system.
date: "2024-01-23T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - race-condition
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32150
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32150
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32150
rules:
  - title: Detect Suspicious FDWSvc File Modification
    description: Detects suspicious modifications to fdwsd.dll, which may indicate an attempt to exploit CVE-2026-32150.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect FDWSvc Child Process
    description: Detects child processes spawned by fdwsd.dll, which is unusual behavior and may indicate code injection.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32150 is a privilege escalation vulnerability affecting the Function Discovery Service (fdwsd.dll) in Windows. The vulnerability is due to a race condition, specifically an improper synchronization issue when the service handles shared resources. A locally authenticated attacker could exploit this flaw by leveraging concurrent execution to manipulate the service's state and gain elevated privileges on the targeted system. The CVSS v3.1 score is 7.0, indicating a high severity. This vulnerability allows an attacker with local access to potentially gain complete control over the system.

## Attack Chain

1.  The attacker gains local access to the targeted Windows system.
2.  The attacker crafts a malicious application or script designed to interact with the Function Discovery Service (fdwsd.dll).
3.  The attacker triggers concurrent execution within the Function Discovery Service by sending multiple requests or signals.
4.  Due to the race condition (CWE-362), the attacker manipulates shared resources within fdwsd.dll before synchronization can occur.
5.  This manipulation leads to an inconsistent state within the service.
6.  The attacker leverages the inconsistent state to overwrite critical system settings or inject malicious code into the service's memory space.
7.  The attacker executes the injected code within the context of the Function Discovery Service, which typically runs with elevated privileges.
8.  The attacker successfully elevates their privileges on the system, gaining the ability to perform administrative tasks, install software, or access sensitive data.

## Impact

Successful exploitation of CVE-2026-32150 allows a local attacker to escalate their privileges to SYSTEM, granting them complete control over the affected Windows system. This could lead to data theft, malware installation, or complete system compromise. The lack of specific victim data makes estimating the breadth of the impact difficult, but given the prevalence of Windows systems, the potential impact is significant.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious FDWSvc File Modification` to identify potential exploitation attempts targeting fdwsd.dll based on unexpected file modifications.
*   Enable Sysmon file event logging to collect the necessary data for the `Detect Suspicious FDWSvc File Modification` rule.
*   Monitor for unexpected processes spawned by the Function Discovery Service (fdwsd.dll) using the `Detect FDWSvc Child Process` Sigma rule to catch potential code injection or privilege escalation attempts.
*   Investigate any instances where a user account is granted unexpected administrator privileges, as this could be a sign of successful exploitation.
*   Refer to Microsoft's advisory for CVE-2026-32150 for official patches and mitigation guidance.
