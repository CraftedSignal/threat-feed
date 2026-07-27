---
title: Unusual Hour for a User to Logon
slug: 2026-07-unusual-logon-hour
description: An Elastic machine learning rule detects unusual user logon times, which can indicate credential compromise or unauthorized access, particularly when attackers operate from different time zones or during non-business hours, prompting investigation into the affected user account and related activities.
date: "2026-07-27T15:32:29Z"
lastmod: "2026-07-27T15:34:20Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - identity-and-access-audit
  - threat-detection
  - machine-learning
  - initial-access
vendors:
  - Elastic
products:
  - Elastic Defend
  - Elastic Agent
  - Kibana
  - Elastic Security
  - Auditd Manager
  - System
  - Windows
  - Fleet
  - Network Packet Capture
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A machine learning job detected a user logging in at a time of day that is unusual for the user. This can be due to credentialed access via a compromised account when the user and the threat actor are in different time zones.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/initial_access_ml_auth_rare_hour_for_a_user_to_logon.toml
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/ml_high_count_events_for_a_host_name.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/ml_linux_anomalous_network_port_activity.toml
updates:
  - at: "2026-07-27T15:33:06Z"
    level: L1
    summary: OS windows; OS linux
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/ml/ml_high_count_events_for_a_host_name.toml
  - at: "2026-07-27T15:34:20Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/ml/ml_linux_anomalous_network_port_activity.toml
---

This brief describes an Elastic Security machine learning rule designed to identify credential compromise and unauthorized access attempts by flagging user logons occurring at unusual times of day for a specific user. Developed by Elastic, this detection leverages data from Elastic Defend or the System integration, making it applicable across various endpoint and system environments. The rule calculates a baseline of normal logon hours for each user and then triggers an alert when a significant deviation is observed. This is crucial for defenders as it can expose attackers utilizing stolen credentials from different geographical locations or performing malicious activities outside typical business hours, potentially leading to unauthorized system access, data exfiltration, or further network penetration. The rule has a minimum stack version of 9.4.0 to use Entity Analytics fields for enhanced accuracy.

## Impact

If an adversary successfully uses compromised credentials to log in at an unusual time, this can lead to unauthorized access to sensitive systems and data. This often precedes further malicious activities such as data exfiltration, lateral movement within the network, or the deployment of malware. While this rule detects anomalous behavior rather than a specific attack, the successful exploitation of valid accounts, as indicated by this anomaly, can result in significant reputational damage, regulatory fines, and operational disruption for affected organizations across any sector. The immediate impact is a breach of trust and unauthorized presence in the environment.

## Recommendation

* Investigate the user account flagged by the "Unusual Hour for a User to Logon" ML rule by contacting the account owner to verify the legitimacy of the logon activity.
* Enable Elastic Defend or the System integration on all relevant endpoints and servers to ensure comprehensive log collection for logon events.
* Review other alerts and user activity associated with the flagged user for the past 48 hours to identify broader suspicious behavior.
* Reset passwords for any confirmed compromised accounts and other potentially affected credentials as part of incident response.
