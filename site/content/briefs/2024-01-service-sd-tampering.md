---
title: Windows Service Security Descriptor Tampering via sc.exe
slug: 2024-01-service-sd-tampering
description: Adversaries may modify service security descriptors to deny access to specific groups, potentially escalating privileges and hindering security services, by using sc.exe to set new deny ACEs (Access Control Entries) on Windows services.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - privilege-escalation
  - windows
vendors:
  - McAfee
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1564
    technique_name: Hide Artifacts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
references:
  - https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
  - https://news.sophos.com/wp-content/uploads/2020/06/glupteba_final-1.pdf
  - https://attack.mitre.org/techniques/T1564/
rules:
  - title: Detect Suspicious sc.exe sdset Execution
    description: Detects suspicious execution of sc.exe with the sdset command and deny ACEs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1564
    data_sources:
      - process_creation
      - windows
  - title: Detect sc.exe Usage to Modify Service Security Descriptor
    description: This rule detects the usage of sc.exe command to modify the security descriptor of a service.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1564
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This analytic detects changes in a service's security descriptor where a new deny ACE (Access Control Entry) has been added using `sc.exe`. The `sc.exe` utility is a command-line tool used for managing Windows services. Adversaries can use `sc.exe` with the `sdset` flag to modify the security descriptor of a service, adding a deny ACE to specific groups (e.g., Authenticated Users, Built-in Administrators, System). This can lead to privilege escalation by preventing legitimate administrators or services from managing the tampered service. The Sophos Glupteba report highlights similar techniques used for defense evasion. This activity is related to MITRE ATT&CK T1564.

## Attack Chain

1.  The adversary gains initial access to the target system.
2.  The adversary identifies a target service with desirable characteristics for manipulation.
3.  The adversary executes `sc.exe` with the `sdset` command to modify the service's security descriptor.
4.  The `sdset` command includes a new deny ACE targeting specific groups like "Authenticated Users" (`IU`), "Built-in Administrators" (`BA`), or "SYSTEM" (`SY`).
5.  The new ACE denies specific permissions (e.g., service start, stop, modify) to the targeted groups.
6.  Legitimate administrators or services are now unable to manage the tampered service due to the deny ACE.
7.  The adversary escalates privileges by exploiting the now-unmanaged service or disabling security products.

## Impact

Successful exploitation allows adversaries to hinder or disable critical security services and gain persistence on the compromised endpoint. By adding deny ACEs to service security descriptors, attackers can effectively blind defenses, prevent remediation efforts, and potentially escalate privileges by abusing the tampered service. This can lead to full system compromise and data exfiltration.

## Recommendation

*   Enable process creation logging with command line arguments via Sysmon or Windows Event Logging (Security 4688) to capture `sc.exe` executions.
*   Deploy the Sigma rule `Detect Suspicious sc.exe sdset Execution` to identify suspicious `sc.exe` commands modifying service security descriptors.
*   Investigate any detected instances of `sc.exe` modifying service security descriptors, especially those targeting sensitive services or using the "sdset" command with deny ACEs.
*   Tune the Sigma rule by adding legitimate applications (e.g., McAfee products) to the filter list to reduce false positives.
