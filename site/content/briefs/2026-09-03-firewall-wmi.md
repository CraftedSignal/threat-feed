---
title: Suspicious Firewall Modification via WMI Provider Host
slug: 2026-09-03-firewall-wmi
description: Detection of unauthorized Windows Firewall rule additions performed by the WMI Provider Host process, a technique associated with defense impairment by ransomware actors.
date: "2026-09-03T13:36:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - ransomware
  - windows-security
  - firewall
affected_os:
  - Windows
  - Windows 11
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_add_rule_wmiprvse.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.004/T1562.004.md#atomic-test-24---set-a-firewall-rule-using-new-netfirewallrule
rules:
  - title: Detect New Firewall Rule Added via WmiPrvSE.EXE
    description: Detects the addition of an 'Allow' firewall rule where the modifying process is the WMI Provider Host (WmiPrvSE.EXE).
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - firewall_as
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for WMI-based firewall rule additions.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides sigma-hq rule definition.
  hunt_leads:
    - lead: Search for Event IDs 2004, 2071, or 2097 where ModifyingApplication is WmiPrvSE.exe.
      technique_id: T1686.003
      data_needed:
        - Windows Security Event Logs (Firewall)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The rule identifies a specific malicious behavioral pattern.
  mitigation_plan:
    - priority: medium_term
      action: Restrict WMI access and enforce code signing for PowerShell/administrative scripts.
      owner: IT Operations
      addresses: Defense impairment T1686.003
      evidence: Standard defensive posture against WMI-based abuse.
---

Defenders should monitor for the addition of new firewall exceptions by the Windows Management Instrumentation (WMI) Provider Host (WmiPrvSE.exe). While legitimate administrative tasks may leverage WMI, this behavior is a known indicator of defense impairment techniques employed by threat actors, such as the Rhysida ransomware group. By utilizing WMI to programmatically modify firewall configurations, attackers can bypass interactive user interfaces to create persistence or enable inbound connectivity for command-and-control (C2) tools. This activity often involves the execution of PowerShell cmdlets or direct interaction with WMI CIM classes (e.g., MSFT_NetFirewallRule) to whitelist malicious processes or network ports. Because WmiPrvSE.exe operates as a system-level host, this activity can sometimes mask the identity of the user or script initiating the request, necessitating correlation with parent process data and audit logs.

## Attack Chain

1. Attacker gains initial code execution on a target Windows endpoint.
2. Attacker identifies the need to enable inbound network access for a secondary tool or persistence mechanism.
3. Attacker uses a PowerShell script or an administrative tool to interact with the WMI service.
4. The WMI service spawns or utilizes the WmiPrvSE.exe process to handle the CIM/WMI request.
5. The WmiPrvSE.exe process executes the command to add a new firewall rule (e.g., New-NetFirewallRule).
6. The Windows Firewall service logs Event ID 2004 or 2071 indicating a rule addition.
7. The firewall exception is active, allowing the attacker to establish C2 communication or facilitate lateral movement.

## Impact

Successful exploitation allows attackers to bypass security boundaries, maintain persistence, and establish reliable communication channels for data exfiltration or secondary payload delivery. This technique has been observed in campaigns by ransomware actors like Rhysida to disable security defenses and ensure reachability of their infrastructure within a compromised environment.

## Recommendation

Detection engineering teams should monitor Windows Firewall event logs specifically for rule modifications initiated by WmiPrvSE.exe.
* Enable Windows Firewall auditing to capture Event IDs 2004, 2071, and 2097.
* Deploy the provided Sigma rule to alert on firewall additions originating from WmiPrvSE.exe.
* Investigate the process lineage of WmiPrvSE.exe to determine if the originating WMI request was triggered by a known administrative script or a suspicious process like powershell.exe or cmd.exe.
