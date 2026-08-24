---
title: Abuse of Windows Filtering Platform to Disable EDR Telemetry
slug: 2026-08-wfp-edr-silencing
description: Adversaries are utilizing the Windows Filtering Platform (WFP) to create block filters that silence security agent communications, preventing the delivery of telemetry and evading detection.
date: "2026-08-24T15:46:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - edr-silencing
  - windows-filtering-platform
affected_os:
  - Windows
rules:
  - title: Detect Windows Filtering Platform Filter Added To Block EDR Process
    description: Detects the addition of a Windows Filtering Platform (WFP) block filter that specifically targets known EDR or security agent processes, which is a technique used to suppress security telemetry.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable auditing for Windows Filtering Platform (Event 5447)
      owner: IT Operations
      due: 72h
      evidence: Required to ingest data for the provided detection logic.
  hunt_leads:
    - lead: Look for any WFP Event 5447 logs containing 'Block' actions over the last 30 days.
      technique_id: T1685
      data_needed:
        - Windows Event Log Security
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Presence of block filters is a strong indicator of WFP tampering.
  mitigation_plan:
    - priority: medium_term
      action: Strictly restrict administrative rights on endpoints.
      owner: IT Operations
      addresses: T1685
      evidence: Manipulation of WFP requires elevated privileges.
---

Adversaries are increasingly abusing the Windows Filtering Platform (WFP) to disrupt the operations of security products. Tools such as EDRSilencer leverage the legitimate capabilities of WFP to dynamically inject filter rules that explicitly block outbound network traffic originating from security agent processes. By creating these block filters, attackers can effectively disable the reporting functionality of EDRs, antivirus solutions, and logging agents without needing to terminate the processes themselves. This technique allows for stealthier persistence of malicious activity, as the security agent remains active in the process list but fails to communicate threat telemetry to central consoles. Defenders must monitor WFP policy modifications for unauthorized block rules targeting security binaries to mitigate this evasion technique.

## Attack Chain

1. The attacker gains administrative or elevated privileges on the target Windows system.
2. The attacker deploys a tool, such as EDRSilencer, capable of interacting with the Windows Filtering Platform API.
3. The tool enumerates running processes to identify security agents (e.g., MsMpEng.exe, xagt.exe, CylanceSvc.exe).
4. The tool constructs a WFP filter rule designed to drop network packets associated with the identified target processes.
5. The tool interacts with the WFP engine via administrative APIs to commit the new filter rule with a "Block" action.
6. The target EDR process continues to run but is prevented from transmitting telemetry to its cloud or management server.
7. The attacker conducts follow-on malicious activity while the EDR remains effectively silenced.

## Impact

Successful abuse of this technique results in the complete loss of visibility into host-based security telemetry. By silencing agents, an attacker can operate on an endpoint undetected, potentially leading to unauthorized data exfiltration, lateral movement, or ransomware deployment without triggering standard security alerts.

## Recommendation

* Enable Windows Security Event Log auditing for Event ID 5447 (Windows Filtering Platform) to capture WFP policy changes.
* Deploy the Sigma rules below to identify the creation of block filters targeting known security processes.
* Establish a baseline for authorized administrative tools that modify WFP filters; investigate any processes outside of this baseline performing such actions.
* Integrate Event ID 5447 into your SIEM monitoring to alert on any WFP rule addition with a "Block" action.
