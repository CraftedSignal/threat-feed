---
title: Modification of Internet Explorer Registry Settings for Persistence
slug: 2026-09-ie-registry-persistence
description: Detection of unauthorized modifications to Internet Explorer registry keys, which can be leveraged by attackers for persistence or defense impairment.
date: "2026-09-01T12:13:03Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - defense-impairment
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: An attacker can abuse this registry key to add a domain to the trusted sites Zone or insert JavaScript for persistence
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: An attacker can abuse this registry key to add a domain to the trusted sites Zone
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_ie.yml
rules:
  - title: Detect Modification of IE Registry Settings
    description: Detects non-standard modifications to Internet Explorer registry settings potentially used for persistence or defense impairment
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
      - persistence
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Identify non-browser processes modifying Internet Settings registry keys
      technique_id: T1112
      data_needed:
        - Registry modification logs with process image path
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Registry keys are normally modified by system processes or browser engines
---

This brief addresses the risk of attackers modifying Internet Explorer (IE) registry keys under the path HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings. While IE is largely deprecated, these registry paths are still utilized by various Windows components for managing zones, proxy settings, and security policies. Attackers may abuse these keys to add malicious domains to the Trusted Sites zone, effectively lowering security restrictions for specific websites, or inject JavaScript via registry values to achieve persistence or execute code within the context of applications that rely on these settings. This activity is often part of a broader post-exploitation phase to maintain access or modify the security posture of an endpoint.

## Impact

Successful exploitation allows attackers to bypass security boundaries, maintain persistence across reboots, and execute scripts in the context of authorized processes that reference these registry settings. This can facilitate further credential theft, data exfiltration, or secondary stage malware execution.

## Recommendation

1. Deploy the provided Sigma rule to detect anomalous registry modifications in the Internet Settings path.
2. Implement an allowlist for known-good configuration tools and processes that modify these registry keys.
3. Enable Sysmon or Windows Event Log auditing (Event ID 13) for registry value set operations.
