---
title: AI-Assisted Multi-Stage Campaigns Targeting Latin American Organizations
slug: 2026-09-ai-assisted-latam-campaigns
description: Two distinct activity clusters (CL-CRI-1131 and CL-CRI-1163) are leveraging LLMs via hosted NextChat instances to troubleshoot and refine post-exploitation scripts and exfiltration infrastructure against entities in the Latin American transportation, government, and financial sectors.
date: "2026-09-03T12:00:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - CL-CRI-1131
  - CL-CRI-1163
  - ai-threat
  - exfiltration
  - latam
  - socks5
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: They executed iterative batch scripts to manipulate and exfiltrate sensitive data.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: 'Phishing: Spearphishing Attachment'
    evidence: We observed that the attackers behind CL-CRI-1163 likely gained initial access through a job-themed phishing compromise.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.002
    technique_name: 'OS Credential Dumping: Security Account Manager'
    evidence: After repeated attempts to dump the Security Account Manager (SAM) registry hive and the domain controller NTDS.dit file...
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090.002
    technique_name: 'Proxy: External Proxy'
    evidence: The attackers employed... tunneling tools, including a Go-based SOCKS5 proxy.
    confidence_band: high
iocs:
  - type: ip
    value: 62.171.185.97
  - type: domain
    value: m-doxa-apodo.duckdns.org
  - type: ip
    value: 178.128.87.160
  - type: ip
    value: 167.148.195.53
ioc_counts:
  domain: 1
  ip: 3
rules:
  - title: Detect Suspicious NextChat Web Interface Hosting
    description: Detects the hosting of NextChat or similar LLM web interfaces on internal hosts, often used by attackers to troubleshoot post-exploitation activities.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block listed C2 domains and IPs at the network perimeter
      owner: SOC
      due: 24h
      evidence: Source provides confirmed malicious infrastructure
  hunt_leads:
    - lead: Search for network traffic to port 3000 on internal assets
      technique_id: T1071.001
      data_needed:
        - Netflow or firewall logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: NextChat interface hosted on attacker infrastructure used for AI-assisted operations
---

Unit 42 researchers identified two significant activity clusters, CL-CRI-1131 and CL-CRI-1163, targeting Latin American organizations. CL-CRI-1131 focuses on transportation, government ministries, and municipal utilities in Mexico and Ecuador, utilizing living-off-the-land techniques and self-hosted NextChat instances for real-time AI-assisted troubleshooting. CL-CRI-1163 targets the Brazilian financial sector using custom Go-based RATs and SOCKS5 proxy tools (e.g., 'SockTz'). Both clusters demonstrate a sophisticated operational shift: attackers are integrating commercial Large Language Models (LLMs) into their post-exploitation workflow. This integration is evidenced by the iterative, trial-and-error generation of batch scripts used to overcome technical hurdles in credential dumping and data collection. Attackers host these AI-interaction interfaces on their own infrastructure, allowing for seamless prompting and debugging during live intrusions. The use of unique dynamic DNS naming conventions and rotated multi-SAN certificates highlights a mature and evolving approach to maintaining persistent, stealthy exfiltration channels.

## Attack Chain

1. Initial access is established via job-themed phishing (CL-CRI-1163) or exploitation of vulnerable web servers (CL-CRI-1131).
2. Attackers perform host discovery and attempt to dump sensitive credentials including SAM and NTDS.dit.
3. Failures in manual extraction lead to the creation of volume shadow copies (vssadmin) to facilitate file access.
4. The operator initiates an LLM interface (NextChat on port 3000) to generate and debug iterative batch scripts for data collection.
5. Scripts are executed to stage data in local collection directories, verified by internal permissions checks.
6. Data is exfiltrated to attacker-controlled C2 infrastructure (e.g., 178.128.87.160) using TLS-encrypted channels.
7. Persistent access is maintained via custom Go-based SOCKS5 proxies like 'SockTz' for ongoing network relay.

## Impact

The campaigns have successfully compromised federal government ministries, municipal water utilities, and financial institutions. These intrusions facilitate the exfiltration of sensitive intelligence and administrative credentials, potentially leading to long-term espionage and financial disruption within the targeted sectors.

## Recommendation

Prioritize the identification of unauthorized AI-interface tools and suspicious proxy activity within internal networks. 

- Hunt for instances of 'NextChat' or similar web-based AI interfaces being hosted on internal or perimeter assets; investigate outbound TCP port 3000 activity.
- Monitor for the execution of iterative batch scripts that utilize 'vssadmin' for volume shadow copy manipulation, often followed by unauthorized file movement.
- Block the identified C2 infrastructure domains and IPs (e.g., m-doxa-*.duckdns.org) at the perimeter DNS and firewall level.
- Investigate any unknown Go-compiled binaries on endpoints, particularly those with filenames matching the 'SockTz' naming convention.
- Enable advanced URL filtering and DNS security to flag traffic to dynamic DNS services commonly utilized by these clusters.
