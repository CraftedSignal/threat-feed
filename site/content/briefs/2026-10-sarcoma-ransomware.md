---
title: Sarcoma Ransomware Group Activity
slug: 2026-10-sarcoma-ransomware
description: The Sarcoma ransomware-as-a-service group continues to target mid-market organizations globally, recently exfiltrating 1.2 TB of data from a new victim in the United States.
date: "2026-10-14T02:21:01Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Sarcoma
tags:
  - ransomware
  - extortion
  - raas
  - discovery
  - exfiltration
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The group utilizes standard ransomware tactics, including exploiting public-facing applications for initial access.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: They perform extensive network discovery using tools like Advanced IP Scanner.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: They exfiltrate data via web services.
    confidence_band: high
iocs:
  - type: domain
    value: sarcomawmawlhov7o5mdhz4eszxxlkyaoiyiy2b5iwxnds2dmb4jakad.onion
ioc_counts:
  domain: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy hunting queries for unauthorized network scanning activity.
      owner: Detection Engineering
      due: 48h
      evidence: Source identifies Advanced IP Scanner usage in Discovery phase.
  hunt_leads:
    - lead: Identification of unusual scheduled tasks created on file servers.
      technique_id: T1547.001
      data_needed:
        - Sysmon Event ID 1 (Process Creation) / Event ID 106 (Scheduled Task)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: TTPs Matrix lists Scheduled Task/Job usage.
---

Sarcoma is a ransomware-as-a-service (RaaS) group that emerged in October 2024. Since its inception, the group has become highly active, with over 140 documented victims across sectors including manufacturing, professional services, healthcare, and retail. Approximately 50 percent of their targeting is focused on organizations within the United States. The group maintains a consistent operational cadence, with an average delay of over 170 days between initial compromise and the public disclosure of stolen data on their leak site. 

Defenders should note that the group relies on a blend of commodity tooling and manual post-exploitation techniques. They frequently target mid-market firms that may lack the resources for robust endpoint monitoring. The group's infrastructure includes a dedicated Tor-based leak site used for the extortion phase of their operations. As of October 2026, the group remains active, and organizations in the identified high-risk sectors should prioritize visibility into credential usage and unusual network discovery activity.

## Attack Chain

1. Initial Access: The group gains entry by exploiting vulnerabilities in public-facing applications or through spearphishing attachments.
2. Discovery: Attackers perform network reconnaissance using tools such as Advanced IP Scanner to map internal assets and identify critical file servers.
3. Credential Access: The group executes OS credential dumping techniques to harvest administrative or service account passwords.
4. Persistence: Persistence is established through the creation of malicious scheduled tasks or by modifying system registry keys.
5. Lateral Movement: Using compromised credentials and Remote Monitoring and Management (RMM) tools, attackers move laterally across the network to access sensitive systems.
6. Collection: Attackers use scripts or manual discovery to identify and archive sensitive data, such as PST files and database dumps.
7. Exfiltration: Stolen data is staged and exfiltrated to attacker-controlled storage using web services to bypass typical egress monitoring.
8. Impact: Ransomware is deployed to encrypt files and inhibit system recovery, followed by the publication of stolen data on the Sarcoma leak site.

## Impact

The Sarcoma group has caused significant operational disruption for at least 142 victims since 2024. Data exfiltration often involves large volumes, with recent incidents involving over 1 TB of sensitive company data. Target organizations face dual-extortion threats, where both system downtime and the public exposure of proprietary or regulated information (such as PST files) pose significant financial and reputational risks.

## Recommendation

* Monitor for the execution of network scanning tools, specifically Advanced IP Scanner, on internal servers to identify the discovery phase of an attack.
* Implement strict access controls and monitor for the creation of unauthorized scheduled tasks, which the group uses for persistence.
* Audit and restrict the use of RMM tools to only approved administrative workstations.
* Monitor network egress traffic for large file transfers to unauthorized web services, aligning with the group's exfiltration TTPs.
* Block traffic to the known Sarcoma leak site domain (sarcomawmawlhov7o5mdhz4eszxxlkyaoiyiy2b5iwxnds2dmb4jakad.onion) at the network perimeter if organizationally feasible.
