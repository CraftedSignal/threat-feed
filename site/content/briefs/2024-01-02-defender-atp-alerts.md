---
title: Microsoft Defender ATP Alert Aggregation and Correlation
slug: 2024-01-02-defender-atp-alerts
description: This analytic aggregates and summarizes alerts from Microsoft Defender ATP, enriching them with MITRE ATT&CK context and risk scoring for improved correlation and risk-based alerting.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - endpoint
  - alert-correlation
  - risk-based-alerting
vendors:
  - Microsoft
products:
  - Microsoft Defender ATP
references:
  - https://learn.microsoft.com/en-us/defender-xdr/api-list-incidents?view=o365-worldwide
  - https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0
  - https://splunkbase.splunk.com/app/6207
  - https://jasonconger.com/splunk-azure-gdi/
rules:
  - title: Detect Suspicious Defender ATP Alerts by Severity
    description: Detects alerts from Microsoft Defender ATP with high or critical severity, indicating potentially significant security incidents.
    platform: sigma
    severity: high
    tactics:
      - detection
    data_sources:
      - MS Defender ATP Alerts
      - splunk
  - title: Detect Defender ATP Alerts with Network Connections
    description: Detects alerts from Microsoft Defender ATP which involve network connections, potentially indicating command and control or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - exfiltration
    data_sources:
      - MS Defender ATP Alerts
      - splunk
rules_count: 2
---

This analytic focuses on enhancing alert data originating from Microsoft Defender ATP. Instead of detecting entirely new activity, it leverages existing alerts to provide a more comprehensive picture of potential threats. The Splunk search aggregates and summarizes alerts, extracting key information like source, file names, severity levels, process command lines, IP addresses, registry keys, signatures, descriptions, unique IDs, and timestamps. The primary goal is to enable security teams to correlate Microsoft Defender ATP alerts with other data sources, contributing to a risk-based alerting strategy within Splunk Enterprise Security. A key aspect is dynamically mapping MITRE ATT&CK techniques associated with the alerts and dynamically setting risk scores based on the alert's severity as determined by Microsoft Defender ATP. The analytic also filters out any alerts where the verdict is "clean" to reduce noise.

## Attack Chain

Since this analytic consumes existing alerts, the attack chain represents a generic endpoint compromise scenario that would trigger Defender ATP alerts.

1. **Initial Access:** A user clicks a malicious link in a phishing email (T1566.001), leading to malware execution.
2. **Execution:** The malicious attachment executes a PowerShell script (T1059.001) to download further payloads.
3. **Persistence:** The PowerShell script creates a scheduled task (T1053.005) to ensure the malware runs after reboot.
4. **Defense Evasion:** The malware attempts to disable Windows Defender Antivirus (T1562.001) using PowerShell commands.
5. **Command and Control:** The malware establishes a connection to a remote C2 server (T1071.001) to receive instructions.
6. **Lateral Movement:** The malware uses SMB (T1021.002) to spread to other machines on the network.
7. **Exfiltration:** Sensitive data is compressed and exfiltrated (T1041) to an external server controlled by the attacker.
8. **Impact:** Data is encrypted or deleted, resulting in a ransomware attack or data breach (T1485).

## Impact

Successful exploitation can lead to data breaches, ransomware attacks, and significant business disruption. The impact depends heavily on the nature of the initial compromise and the attacker's objectives. While the number of victims is unknown, organizations relying solely on default Microsoft Defender ATP configurations without correlation and enrichment are at higher risk. The affected sectors are broad, as endpoint compromise is a common attack vector across all industries. Failure to detect and respond to these alerts promptly can result in significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the provided Splunk search to your Splunk environment and tune the `ms_defender_atp_alerts_filter` macro to filter out known false positives in your environment.
*   Configure the Splunk Add-on for Microsoft Security to ingest alerts from Microsoft Defender ATP using the `ms:defender:atp:alerts` sourcetype, as detailed in the "how_to_implement" section.
*   Implement the Sigma rule `Detect Suspicious Defender ATP Alerts by Severity` to prioritize high and critical alerts for immediate investigation.
*   Investigate any alerts where the risk score, dynamically calculated from the alert severity, exceeds a threshold appropriate for your organization.
