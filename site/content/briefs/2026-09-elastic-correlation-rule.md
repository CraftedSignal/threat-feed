---
title: Cross-Telemetry Correlation of Endpoint and Network Security Alerts
slug: 2026-09-elastic-correlation-rule
description: Detection engineering logic that correlates Elastic Defend endpoint alerts with network security events from PAN-OS, FortiGate, and Suricata to identify potentially compromised hosts based on multi-source telemetry.
date: "2026-09-18T19:21:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - correlation
  - multi-datasource
  - network-security
  - endpoint-security
vendors:
  - Elastic
  - Palo Alto Networks
  - Fortinet
  - OISF
products:
  - Elastic Defend (8.18+)
  - PAN-OS
  - FortiGate
  - Suricata
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This rule correlate any Elastic Defend alert with a set of suspicious events from Network security devices like Palo Alto Networks (PANW), Fortinet Fortigate and Suricata by host.ip and source.ip.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Fortigate suspicious events (event.action in ('outbreak-prevention', 'infected', 'blocked') or message like 'backdoor*' ... 'exploit_detected').
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/multiple_alerts_elastic_defend_netsecurity_by_host.toml
  - https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-data-volume-for-elastic-endpoint#host-fields
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy ESQL correlation rule to SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Rule ID 0bca7e73-e1b5-4fb2-801b-9b5f5be20dfe
  mitigation_plan:
    - priority: immediate
      action: Enable host.ip collection in Elastic Defend configuration
      owner: IT Operations
      addresses: Rule prerequisite
      evidence: Source documentation for version 8.18+
---

This detection brief details a higher-order correlation rule designed for the Elastic Security platform to identify system compromises by analyzing telemetry across heterogeneous security sources. The rule monitors for concurrent suspicious activity reported by both host-based endpoint protection (Elastic Defend) and perimeter or network-level security controls, including Palo Alto Networks PAN-OS, Fortinet FortiGate, and Suricata.

By requiring that a host triggers distinct alerts across at least two separate security modules, the logic significantly reduces the noise associated with isolated alerts. The rule utilizes ESQL to normalize IP-based telemetry across these disparate data sources, focusing on high-risk indicators such as command and control (C2) communication, malware detection, unauthorized remote access, and exploit attempts. This approach is intended to pinpoint hosts exhibiting behavior characteristic of an active adversary, such as lateral movement or data staging, which often trigger alerts on both the compromised endpoint and the gateway monitoring its traffic.

## Impact

Successful attacks identified by this correlation logic typically involve advanced persistent threats or automated malware campaigns that interact with external infrastructure. If left unmitigated, these incidents could lead to full system compromise, exfiltration of sensitive data, or the use of the host as a staging point for broader lateral movement within the network. This rule assists security operations centers (SOC) in prioritizing high-fidelity alerts where multiple security layers have independently flagged a specific asset as suspicious.

## Recommendation

Prioritized actions for detection engineering and incident response:

- Deploy the ESQL correlation rule to your Elastic Security SIEM to unify alerts from Elastic Defend and existing network security appliances.
- Enable host IP collection for Elastic Defend (version 8.18+) to ensure the `host.ip` field is populated, as this is a prerequisite for the correlation logic.
- Tune the rule by identifying and excluding known benign noise sources, such as administrative scanning tools or legitimate internal vulnerability management scanners that may trigger overlapping network and endpoint alerts.
- Use the gathered context from the rule (including process command lines and destination IPs) to drive proactive threat hunting across the environment for related IOCs.
