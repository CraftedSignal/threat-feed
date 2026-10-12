---
title: Detection of Unauthorized Windows Proxy Registry Modifications
slug: 2026-10-windows-registry-proxy-modification
description: Adversaries, including those deploying the DarkGate malware, modify the 'Internet Settings\ProxyServer' registry key to establish covert, proxied Command and Control communication channels.
date: "2026-10-12T18:13:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The following analytic detects modifications to the Windows registry key for setting up a proxy server.
    confidence_band: high
rules:
  - title: Detect Windows Registry ProxyServer Modification
    description: Detects modifications to the Windows registry key for setting up a proxy server, which is a technique used by malware like DarkGate to establish C2 communication.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
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
    - action: Deploy Sigma rule for registry modification monitoring
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation of T1112
  hunt_leads:
    - lead: Search for historical changes to the Internet Settings\ProxyServer registry path
      technique_id: T1112
      data_needed:
        - Registry modification logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Registry key identified as target for C2 configuration
---

This threat brief focuses on the exploitation of Windows registry modifications to configure proxy servers, a technique frequently observed in malware campaigns such as DarkGate. By altering the "Internet Settings\ProxyServer" registry path, attackers can force host traffic through an adversary-controlled proxy. This configuration facilitates covert Command and Control (C2) communication, bypassing standard network perimeter defenses and potentially masking data exfiltration. Because this registry key is rarely modified by legitimate end-user activity, changes to this path serve as a high-fidelity indicator of malicious persistence or exfiltration preparation. Security teams should monitor for unauthorized registry writes to this specific hive to disrupt attacker communication channels and identify compromised endpoints.

## Attack Chain

1. The adversary gains initial access to the Windows host through phishing or exploitation.
2. The attacker executes a payload or script with sufficient privileges to modify the Windows registry.
3. The malware identifies the current user's Internet settings located in the registry hive.
4. The malicious process invokes `RegSetValueEx` or a similar API to modify "Internet Settings\ProxyServer".
5. The attacker configures the registry value to point to an external, adversary-controlled proxy server.
6. Subsequent system or application network traffic is routed through the specified proxy.
7. The attacker establishes a persistent, covert C2 channel for tasking and exfiltration.

## Impact

Successful modification of the proxy registry settings allows attackers to establish covert persistence on the infected host. This technique has been observed in campaigns involving DarkGate malware, where it is used to facilitate exfiltration and C2 communication. If left undetected, this allows attackers to maintain long-term, stealthy access, potentially leading to widespread data theft or further lateral movement within the target environment.

## Recommendation

* Deploy the provided Sigma rule to detect modifications to the "Internet Settings\ProxyServer" registry key using Sysmon Event ID 13.
* Enable process-creation and registry-modification logging (Sysmon Event ID 13) on all high-value Windows endpoints.
* Investigate the process responsible for any modification to "ProxyServer" registry keys to determine if the activity is originating from legitimate administrative tools or unauthorized malware.
* Use the provided drilldown searches to identify affected hosts and cross-reference them with risk-based alerts in the SIEM.
