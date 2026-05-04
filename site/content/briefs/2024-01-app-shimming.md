---
title: Potential Application Shimming via Sdbinst
slug: 2024-01-app-shimming
description: Attackers abuse the Application Shim functionality in Windows by using `sdbinst.exe` with malicious arguments to achieve persistence and execute arbitrary code within legitimate Windows processes.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - application-shimming
  - windows
vendors:
  - Microsoft
  - Citrix
products:
  - Windows
  - Citrix Workspace
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_via_application_shimming.toml
  - https://attack.mitre.org/techniques/T1546/
  - https://attack.mitre.org/techniques/T1546/011/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: Potential Application Shimming via Sdbinst
    description: Detects potential application shimming attempts by monitoring for suspicious sdbinst.exe executions without benign arguments.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.011
    data_sources:
      - process_creation
      - windows
  - title: Potential Application Shimming via Sdbinst - Alternate Location
    description: Detects potential application shimming attempts by monitoring for suspicious sdbinst.exe executions without benign arguments from SysWOW64.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.011
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Application shimming is a compatibility mechanism in Windows that allows older applications to run on newer operating systems. However, attackers can abuse this functionality to gain persistence and execute arbitrary code in the context of legitimate Windows processes. This is achieved by using the `sdbinst.exe` utility to install malicious application compatibility databases (.sdb files). These databases can then be used to inject malicious code into targeted applications. The detection rule focuses on identifying suspicious invocations of `sdbinst.exe` with arguments that do not include benign flags, indicating potential misuse of the application shimming mechanism. This technique is stealthy because it allows attackers to execute code within trusted processes, making it harder to detect.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., via phishing or exploiting a vulnerability).
2.  The attacker deploys or creates a malicious .sdb file containing code to be injected.
3.  The attacker uses `sdbinst.exe` to install the malicious .sdb file. The command line arguments often lack common benign flags like "-m", "-bg", or "-mm".
4.  The operating system loads the shim database when the targeted application is launched.
5.  The malicious code within the .sdb file is executed in the context of the targeted application.
6.  The attacker gains persistent access to the system, as the shim is loaded each time the targeted application is executed.
7.  The attacker performs malicious activities, such as data exfiltration, lateral movement, or further exploitation.

## Impact

A successful application shimming attack can allow an attacker to maintain persistent access to a compromised system. This can lead to data theft, system compromise, and further malicious activities. Because the malicious code executes within a trusted process, detection can be challenging, and the attacker can potentially bypass security controls. While the number of victims is unknown, this technique is particularly effective against organizations that rely on specific applications, as the attacker can target those applications for persistence.

## Recommendation

*   Deploy the Sigma rule "Potential Application Shimming via Sdbinst" to your SIEM to detect suspicious invocations of `sdbinst.exe`.
*   Enable Sysmon process creation logging to capture the command-line arguments of `sdbinst.exe` executions, which is required for the Sigma rule.
*   Investigate and remove any unauthorized or suspicious application compatibility databases (.sdb files) found on systems.
*   Implement enhanced monitoring and logging for `sdbinst.exe` executions across the network to detect and respond to future attempts at application shimming.
*   Regularly review and update the list of exceptions to ensure that only verified and necessary exclusions are maintained to avoid overlooking genuine threats.
