---
title: Bitsadmin Activity to Uncommon Top-Level Domains
slug: 2026-10-bitsadmin-uncommon-tld
description: Detection of Windows Background Intelligent Transfer Service (BITS) administrative utility usage targeting suspicious or non-standard top-level domains.
date: "2026-10-02T04:09:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-and-control
  - execution
  - stealth
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The rule identifies Bitsadmin network activity over web protocols to uncommon TLDs.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1197
    technique_name: BITS Jobs
    evidence: The detection targets Bitsadmin, which is the primary administrative tool for BITS.
    confidence_band: high
rules:
  - title: Detect Bitsadmin Activity to Uncommon TLDs
    description: Detects Bitsadmin network connections using the Microsoft BITS User-Agent to domains with non-standard or uncommon TLDs.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - persistence
    techniques:
      - T1071.001
      - T1197
    data_sources:
      - proxy
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for BITS activity to uncommon TLDs
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict BITS communication to known-good domains via proxy/firewall
      owner: Network Security
      evidence: General security best practices for BITS
---

The Bitsadmin utility is a command-line tool used to create, download, or upload jobs using the Windows Background Intelligent Transfer Service (BITS). While BITS is a legitimate component for software updates and background file transfers, it is frequently abused by adversaries for C2 communication, data exfiltration, and malware delivery. This detection focuses on identifying BITS activity directed toward uncommon or suspicious top-level domains (TLDs) that fall outside of standard enterprise or trusted update traffic. Because BITS typically communicates with established infrastructure like Microsoft update endpoints or trusted CDN domains, connections to unusual TLDs may indicate malicious activity, such as staged malware downloads or beaconing to actor-controlled infrastructure. Defenders should monitor proxy logs for the specific 'Microsoft BITS/' User-Agent string to identify and investigate potential BITS abuse.

## Impact

Successful exploitation of BITS for C2 or file transfer allows attackers to blend in with legitimate system traffic, potentially bypassing traditional network perimeter controls and achieving long-term persistence within an environment.

## Recommendation

Deploy the provided Sigma rule to your proxy logs to identify BITS traffic directed to non-standard domains. Use the identified logs to investigate the destination domains and the associated file transfer activity.

- Deploy the Sigma rule below to proxy log aggregators to alert on suspicious BITS traffic.
- Baseline common BITS traffic patterns to filter out legitimate, authorized regional TLDs that may trigger false positives in your specific environment.
