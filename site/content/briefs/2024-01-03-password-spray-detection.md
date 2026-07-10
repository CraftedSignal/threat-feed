---
title: Password Spray Attack Detection via 3-Sigma Anomaly
slug: 2024-01-03-password-spray-detection
description: This analytic detects password spraying attacks by identifying an unusual volume of failed authentication attempts from a single source using a 3-sigma deviation from the average, leveraging the Authentication Data Model for broad CIM-mapped event coverage.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - password-spraying
  - credential-access
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://attack.mitre.org/techniques/T1110/003/
rules:
  - title: Detect Password Spray Attempts by Source IP
    description: Detects password spray attacks by identifying source IPs with a high number of failed authentication attempts against unique user accounts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - authentication
      - windows
  - title: Detect Password Spray Attempts by User Agent
    description: Detects password spray attacks by identifying unusual user agents associated with failed authentication attempts against multiple accounts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - authentication
      - windows
rules_count: 2
---

This detection focuses on identifying password spraying attacks, where attackers attempt to compromise multiple accounts using a small set of common passwords. The analytic uses a 3-sigma approach to detect anomalies in failed authentication attempts, specifically looking for sources exhibiting a significantly higher-than-average number of failed logins against unique accounts. The detection leverages the Common Information Model (CIM) to normalize authentication data, ensuring broad coverage across different log sources. It aims to identify attackers attempting to evade account lockout policies by distributing their efforts across numerous accounts. This behavior is flagged by observing failed authentications, specifically targeting endpoints as the source of the malicious activity. The detection uses statistical analysis to identify deviations from normal authentication patterns.

## Attack Chain

1.  The attacker gains initial network access (e.g., VPN, compromised system).
2.  The attacker initiates authentication attempts against multiple user accounts.
3.  The attacker uses common or weak passwords for each attempt, changing the target user for each attempt.
4.  Windows Event Log Security logs failed authentication attempts (Event ID 4625).
5.  The SIEM aggregates and analyzes authentication failure events, grouping them by source IP address and time window.
6.  The detection calculates the average and standard deviation of unique accounts targeted by each source.
7.  The detection flags sources with unique account counts exceeding three standard deviations above the average.
8.  Successful compromise leads to account takeover and potential data exfiltration, lateral movement, or other malicious activities.

## Impact

Successful password spraying attacks can lead to widespread account compromise, enabling attackers to access sensitive data, disrupt services, and launch further attacks within the organization. The number of affected accounts can range from a few to hundreds, depending on the attacker's persistence and the effectiveness of the organization's password policies. Sectors that rely heavily on online services and store sensitive user data, such as finance, healthcare, and e-commerce, are particularly vulnerable. A successful attack can lead to data breaches, financial losses, and reputational damage.

## Recommendation

*   Ensure authentication data is CIM-mapped, as referenced in the search query, and the source IP address is populated in the `src` field to ensure proper functionality of the detection analytic.
*   Implement the provided Splunk search query in your SIEM, operating on a 5-minute schedule, looking back 70 minutes, as recommended in the `how_to_implement` section. Configure 70-minute throttling on the `_time` and `counter` fields.
*   Deploy the Sigma rule "Detect Password Spray Attempts by Source IP" to complement the Splunk search and provide cross-platform detection capabilities.
*   Review and tune the threshold for `unique_accounts` and the standard deviation multiplier in the Sigma rule based on your environment's baseline authentication activity.
