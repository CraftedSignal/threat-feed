---
title: Braodo Stealer Python-Based Credential Harvesting
slug: 2026-10-braodo-stealer
description: The Braodo Stealer is a Python-based credential-harvesting malware that masquerades as legitimate Python processes executing from suspicious directories to exfiltrate advertising data via Meta's Graph API.
date: "2026-10-19T02:52:13Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Braodo Stealer
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1586.001
    technique_name: 'Compromise Accounts: Social Media'
    evidence: The Braodo Stealer abuses authenticated browser sessions to query the Meta Graph API.
    confidence_band: high
references:
  - https://www.splunk.com/en_us/blog/security/cracking-braodo-stealer-analyzing-python-malware-and-its-obfuscated-loader.html
iocs:
  - type: domain
    value: '*.facebook.com'
  - type: domain
    value: '*.facebook.net'
  - type: domain
    value: '*.facebook.org'
  - type: domain
    value: '*.fb.com'
  - type: domain
    value: '*.fbcd.net'
  - type: domain
    value: '*.fbsbx.com'
  - type: domain
    value: '*.fbstatic-a.akamaihd.net'
  - type: domain
    value: '*.tfbw.net'
ioc_counts:
  domain: 8
rules:
  - title: Detect Outbound Connections from Python in Suspicious Directories
    description: Detects outbound network connections from Python processes executing from suspicious or non-standard file paths.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1586.001
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
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 24h
  hunt_leads:
    - lead: Search for python.exe processes executing from non-standard directories
      technique_id: T1586.001
      data_needed:
        - Sysmon EID 1/3
      priority: high
      confidence: high
      disposition: hunt_now
---

The Braodo Stealer is a Python-based credential-harvesting malware identified in October 2026 that targets authenticated browser sessions to compromise user accounts. The malware specifically leverages the Meta Graph API to enumerate information related to the victim's Facebook and Meta advertising infrastructure. The threat is characterized by its execution from non-standard or highly suspicious directories on Windows systems, such as the Recycle Bin, Prefetch folders, or user-accessible public directories. By masquerading as standard Python binaries (e.g., python.exe, pythonw.exe), the malware attempts to blend into legitimate administrative or development activity. This campaign highlights the importance of monitoring process execution paths, especially for scripting engines that are frequently abused by attackers to facilitate command-and-control communication with legitimate social media infrastructure.

## Attack Chain

1. Initial infection typically via a dropper or malicious payload delivery mechanism.
2. The malware drops a Python interpreter and supporting scripts into a non-standard location such as C:\Users\Public\ or C:\Windows\Temp\.
3. The malware executes using a legitimate Python process name like python.exe or pythonw.exe to maintain a lower profile.
4. It scans the host environment for existing browser session cookies to identify active Meta or Facebook authentication tokens.
5. The Python script initiates an outbound connection to social media domains using its hijacked session context.
6. It interacts with the Meta Graph API to enumerate advertising account details and connected metadata.
7. Exfiltration of harvested credentials and advertising intelligence occurs over outbound HTTPS connections to Meta-affiliated infrastructure.

## Impact

Successful execution of Braodo Stealer results in the compromise of victim credentials and the potential takeover of Facebook or Meta advertising accounts. This allows attackers to perform unauthorized operations, such as managing ads or exfiltrating sensitive organizational financial data stored within advertising dashboards. Given the reliance on authenticated sessions, the impact can bypass standard credential-based authentication.

## Recommendation

Prioritize the implementation of process path monitoring for scripting environments.
- Deploy the provided Sigma rule to detect outbound connections from Python processes spawned from suspicious directories.
- Enable Sysmon Event ID 3 (Network Connection) logging across all endpoints to capture destination domains and associated processes.
- Monitor for Python-related binaries executing from directories such as \$Recycle.Bin, \PerfLogs, or \Windows\Fonts.
- Restrict write access to sensitive system directories to prevent the placement of malicious scripts by non-privileged processes.
