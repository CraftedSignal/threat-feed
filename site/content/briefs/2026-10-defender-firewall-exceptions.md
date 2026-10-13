---
title: Impairment of Microsoft Defender Firewall via Registry Modification
slug: 2026-10-defender-firewall-exceptions
description: Adversaries modify specific registry keys to disable Microsoft Defender Firewall exceptions, potentially enabling unauthorized lateral movement or command-and-control communication.
date: "2026-10-13T14:46:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - windows
  - firewall
  - registry
affected_os:
  - Windows
rules:
  - title: Detect Modification to Allow Microsoft Defender Firewall Exceptions
    description: Detects the modification of the DoNotAllowExceptions registry value to 0, which re-enables application and port exceptions in the Microsoft Defender Firewall.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for registry-based firewall impairment.
      owner: Detection Engineering
      due: 48h
      evidence: Sigma source provided.
  hunt_leads:
    - lead: Search for historical registry modifications to DoNotAllowExceptions across the fleet.
      technique_id: T1686.003
      data_needed:
        - Registry modification logs (Sysmon EID 13)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source highlights registry manipulation as a malicious technique.
---

Threat actors have been observed modifying the Windows Registry to weaken system security posture by disabling restrictions on Microsoft Defender Firewall exceptions. By setting the 'DoNotAllowExceptions' value to '0' (DWORD 0x00000000) under the 'Services\SharedAccess\Parameters\FirewallPolicy' registry hive, an attacker can bypass existing firewall policies that normally block unsolicited inbound or outbound traffic. This technique is frequently employed by various malware strains, including Zbot variants, to maintain persistence or open communication channels that would otherwise be restricted by a hardened security profile. Security teams should monitor for unauthorized registry modifications targeting this path, particularly when the modification originates from processes other than legitimate Windows service hosts.

## Impact

Successful exploitation allows attackers to bypass network security controls, facilitating the establishment of command-and-control channels or unauthorized lateral movement within the environment. This activity is often associated with malware that aims to disable local security features, thereby increasing the risk of data exfiltration and further payload delivery.

## Recommendation

- Deploy the provided Sigma rule to monitor for unauthorized modifications to the 'DoNotAllowExceptions' registry key.
- Implement a policy of least privilege to restrict non-administrative users and suspicious processes from modifying registry keys under 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\'.
- Baseline legitimate software installation processes that may require firewall exceptions to ensure they do not perform this specific registry modification outside of defined maintenance windows.
