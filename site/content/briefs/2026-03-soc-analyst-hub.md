---
title: SOC Analyst Toolkit with Threat Hunting Queries
slug: 2026-03-soc-analyst-hub
description: A free, offline SOC toolkit aimed at Tier 1 analysts includes IR checklists, triage playbooks, and threat hunting guides mapped to MITRE ATT&CK, with Splunk and Elastic queries for threats such as Kerberoasting, Pass-the-Hash, LOLBAS, scheduled task persistence, and C2 on non-standard ports.
date: "2026-03-18T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - low
tags:
  - soc
  - blueteam
  - threat-hunting
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rw71as/built_a_free_offline_soc_analyst_hub_for_tier_1/
  - https://cross-samuel1.github.io/soc-analyst-hub/
  - https://github.com/cross-samuel1/soc-analyst-hub
iocs:
  - type: url
    value: https://cross-samuel1.github.io/soc-analyst-hub/
  - type: url
    value: https://github.com/cross-samuel1/soc-analyst-hub
ioc_counts:
  url: 2
rules:
  - title: Detect Suspicious Scheduled Task Creation
    description: Detects the creation of scheduled tasks that may be used for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Connections to Non-Standard Ports
    description: Detects network connections to common command and control ports.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A security practitioner has released a free, offline SOC toolkit intended for Tier 1 analysts and those new to blue team operations. This toolkit, contained within a single HTML file, provides resources for incident response, alert triage, threat hunting, and analyst onboarding. Released in March 2026, the toolkit includes interactive IR checklists for common incident types (Phishing, Malware, Brute Force, Data Exfil, Suspicious PowerShell), alert triage playbooks with decision trees, threat hunting guides mapped to MITRE ATT&CK, and a structured curriculum for new Tier 1 hires. The threat hunting guides are noteworthy, as they include Splunk and Elastic queries for specific attack techniques like Kerberoasting, Pass-the-Hash, LOLBAS abuse, scheduled task persistence, and C2 communication on non-standard ports. Defenders can leverage the shared hunting queries to enhance their detection capabilities.

## Attack Chain

This toolkit is designed to aid in the *detection* of the following attack chains:

1.  **Initial Access:** (Phishing, Malware) An attacker gains initial access through methods such as phishing emails or malware-infected attachments.
2.  **Credential Access:** (Kerberoasting, Pass-the-Hash) After gaining initial access, the attacker attempts to harvest credentials using techniques like Kerberoasting to target service accounts or Pass-the-Hash to reuse existing credentials.
3.  **Lateral Movement:** (Pass-the-Hash) Using compromised credentials, the attacker moves laterally within the network, accessing additional systems and resources.
4.  **Execution:** (LOLBAS) The attacker utilizes Living-Off-The-Land Binaries and Scripts (LOLBAS) to execute malicious commands and evade detection.
5.  **Persistence:** (Scheduled Task Persistence) The attacker establishes persistence by creating scheduled tasks that execute malicious code at regular intervals.
6.  **Command and Control:** (C2 on non-standard ports) The attacker establishes a command and control channel, communicating with compromised systems over non-standard ports to evade detection.
7.  **Exfiltration:** (Data Exfil) The attacker exfiltrates sensitive data from the compromised systems.
8.  **Impact:** (Data Exfil) The attacker achieves their final objective of data exfiltration, resulting in data loss or exposure.

## Impact

The toolkit helps defenders to mitigate the impact of attacks by providing resources for incident response, alert triage, and threat hunting. Successful implementation of the toolkit's recommendations can lead to faster detection and containment of security incidents, reducing the potential for data breaches, financial losses, and reputational damage.

## Recommendation

*   Review the threat hunting guides within the toolkit and adapt the provided Splunk and Elastic queries for Kerberoasting, Pass-the-Hash, LOLBAS, scheduled task persistence, and C2 on non-standard ports to your environment.
*   Utilize the provided IR Checklists (Phishing, Malware, Brute Force, Data Exfil, Suspicious PowerShell) to standardize and improve incident response procedures.
*   Customize and integrate the Alert Triage Playbooks into your existing security operations workflows to assist with the analysis of alerts related to impossible travel, lateral movement, and DNS beaconing.
