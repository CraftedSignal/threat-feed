---
title: 'FortiBleed Campaign: 73,932 FortiGate Systems Credentials Exposed'
slug: 2026-06-fortibleed-credentials-leak
description: A Russian-speaking threat group utilized a large dataset of administrative and VPN credentials, likely sourced from exposed FortiGate configuration files and active credential harvesting, to access government, critical infrastructure, and multinational corporate networks, resulting in widespread data exfiltration.
date: "2026-06-19T14:46:20Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - Russian-speaking threat group
tags:
  - credential-theft
  - fortigate
  - fortios
  - state-sponsored
  - espionage
  - data-exfiltration
  - russian-speaking
  - critical-infrastructure
  - government
vendors:
  - Fortinet
products:
  - FortiGate
  - FortiOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
references:
  - https://www.recordedfuture.com/blog/critical-fortibleed-campaign
iocs:
  - type: ip
    value: 85.11.187.8
ioc_counts:
  ip: 1
rules:
  - title: Detect Malicious IP in Network Connections
    description: Detects network connections to or from the IP address 85.11.187.8, which has been linked to the FortiBleed campaign for credential harvesting and follow-on intrusions.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Execution of AD/Credential Enumeration Scripts
    description: Detects the execution of known Active Directory and credential enumeration Python scripts (ad_enum.py, ad_full_audit.py) or password spraying scripts (spray_*.py) identified in the FortiBleed campaign infrastructure.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1087.002
      - T1110.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Creation/Modification of FortiBleed Attack Tools
    description: Detects the creation or modification of specific files identified as part of the FortiBleed campaign's credential harvesting, cracking, and data collection toolkit (e.g., fg_capture.log, bot.py, backup_dfs.py).
    platform: sigma
    severity: high
    tactics:
      - collection
      - persistence
    techniques:
      - T1005
      - T1562.001
    data_sources:
      - file_event
      - windows
rules_count: 3
---

A Russian-speaking threat group has been attributed to the "FortiBleed" campaign, which involves a massive dataset containing valid administrative and SSL VPN credentials for approximately 73,932 Fortinet FortiGate firewalls across 194 countries and over 21,600 domains. Disclosed on June 13, 2026, by researcher Volodymyr Diachenko, this campaign leverages credentials likely obtained from exported FortiGate configuration files and active credential harvesting against FortiGate and MSSQL systems. The threat group used a 45-GPU cluster for offline hash cracking, enabling access to sensitive internal networks, including government, critical infrastructure, and multinational corporations. The scope and verified authenticity of these credentials make this a high-priority incident, as many affected devices remain online and internet-exposed, posing an immediate threat of espionage and data exfiltration.

## Attack Chain

1.  **Credential Harvesting & Exposure**: Threat actors obtained a dataset comprising FortiGate administrative and SSL VPN credentials, likely sourced from exposed FortiGate configuration files and hashes intercepted during large-scale credential attempts (1.16 billion against FortiGate, 2.1 billion against MSSQL).
2.  **Offline Credential Cracking**: A 45-GPU cluster managed through Hashtopolis was utilized to crack the collected SSL VPN authentication hashes, successfully recovering plaintext administrative and VPN credentials.
3.  **Initial Access with Valid Accounts**: Using the recovered plaintext credentials, threat actors gained unauthorized access to FortiGate management interfaces and internal Active Directory environments.
4.  **Lateral Movement & Discovery**: Once inside, attackers deployed Active Directory and LDAP enumeration scripts (e.g., `ad_enum.py`, `ad_full_audit.py`) and performed password spraying (`spray_*.sh`, `spray_*.py`) to expand their access and identify additional targets and sensitive data within the network.
5.  **Data Collection & Staging**: SMB/DFS collection scripts (e.g., `backup_dfs.py`, `spider.py`) were used to identify and gather sensitive data across the network, potentially staging it for exfiltration.
6.  **Data Exfiltration**: Classified documents and other sensitive information were exfiltrated from compromised organizations, including a Turkish NATO defense contractor.
7.  **Defense Evasion**: Threat actors employed log-clearing markers to remove traces of their activity from compromised systems, hindering detection and forensic analysis.

## Impact

The FortiBleed campaign has resulted in the exposure of credentials for 73,932 FortiGate firewall URLs across 194 countries and over 21,600 domains. Verified compromises include organizations in government, telecommunications, financial services, healthcare, manufacturing, and critical infrastructure sectors, with reported impacts in Japan, Taiwan, Vietnam, Iraq, and Türkiye. A Turkish NATO defense contractor suffered exfiltration of classified documents, highlighting the potential for state-sponsored espionage. The offline nature of credential cracking means initial credential theft may not be logged, making detection of the initial compromise challenging. Continued online exposure of affected devices with verified credentials poses an ongoing, severe risk.

## Recommendation

*   Rotate all FortiGate administrative and SSL VPN credentials immediately, especially for those identified as exposed.
*   Enforce multi-factor authentication (MFA) on all FortiGate remote and administrative access points to mitigate the impact of compromised credentials.
*   Deploy the Sigma rule "Detect Malicious IP in Network Connections" to identify and block traffic associated with `85.11.187.8` at your network perimeter.
*   Deploy the Sigma rule "Detect Execution of AD/Credential Enumeration Scripts" to your Windows endpoints to alert on post-exploitation activity involving `ad_enum.py` or similar scripts.
*   Deploy the Sigma rule "Detect Creation/Modification of FortiBleed Attack Tools" to monitor file system activity for the presence of attacker tools like `fg_capture.log` or `bot.py`.
*   Review Fortinet logs for unusual login attempts, administrative sessions, configuration changes, and newly created accounts.
*   Restrict or remove internet exposure for FortiGate management interfaces to reduce attack surface.
*   Patch FortiOS to the latest available version to address any underlying vulnerabilities that might have facilitated configuration file exposure.
