---
title: Abuse of Microsoft Defender Firewall Registry Keys for Unauthorized Application Access
slug: 2026-10-defender-firewall-registry-persistence
description: Adversaries modify Windows Registry keys related to Microsoft Defender Firewall 'AuthorizedApplications' to bypass network restrictions and ensure persistence for malicious binaries.
date: "2026-10-13T14:46:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - windows-security
  - persistence
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_defender_firewall_add_exception.yml
rules:
  - title: Detect Unauthorized Microsoft Defender Firewall Exception via Registry
    description: Detects the modification of registry keys under FirewallPolicy to add an authorized application, which can be used to bypass firewall security
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule for FirewallPolicy registry modification
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in the brief
  hunt_leads:
    - lead: Search registry logs for modifications to AuthorizedApplications\List keys initiated by non-system processes
      technique_id: T1686
      data_needed:
        - Registry modification logs (EID 12/13)
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Rule logic targets this exact registry path
  mitigation_plan:
    - priority: medium
      action: Restrict write access to HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy to privileged administrators only
      owner: IT Operations
      addresses: Persistence and Defense Evasion TTPs
      evidence: Standard administrative hardening practice
  gaps:
    - Need to validate existing authorized applications to establish a baseline
---

Attackers and malware, including historical samples like variants of Zbot, exploit the Windows Registry to modify Microsoft Defender Firewall configuration. By writing to the 'AuthorizedApplications\List' keys under 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy', an attacker can programmatically grant an arbitrary executable network access. This technique allows a malicious process to bypass firewall restrictions without user interaction or a formal interface prompt. Because these changes reside in the registry, they can persist across system reboots. This activity is a classic form of defense impairment, ensuring that command-and-control communication remains viable even when local network filtering policies would otherwise block the activity. Defenders should monitor registry write operations to the SharedAccess parameters hive to detect unauthorized changes to firewall exceptions.

## Impact

Successful exploitation allows malicious binaries to bypass host-based network egress restrictions. This facilitates persistent command-and-control communications and exfiltration of sensitive data from the targeted host. These modifications are often seen in the context of trojans and spyware seeking to maintain stealthy network connectivity while evading detection by standard security policy configurations.

## Recommendation

- Deploy the provided Sigma rule to monitor 'registry_set' events targeting 'FirewallPolicy' keys.
- Implement monitoring for processes creating or modifying registry keys under 'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\'.
- Audit existing authorized application exceptions periodically to identify non-standard entries or orphaned application paths.
