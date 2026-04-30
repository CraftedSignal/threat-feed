---
title: Unusual City for Azure Activity Logs Event
slug: 2026-06-unusual-azure-city
description: A machine learning job detected Azure Activity Logs activity that, while not inherently suspicious or abnormal, is sourcing from a geolocation (city) that is unusual for the event action, indicating potential compromised credentials.
date: "2026-04-02T13:35:13Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - azure
  - cloud
  - anomaly-detection
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
rules:
  - title: Azure Activity Logs - Unusual City for Event Action
    description: Detects Azure Activity Logs events originating from an unusual city for the specific action, potentially indicating compromised credentials.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - azure
  - title: Azure ARM - Privileged Role Assignment from Unusual City
    description: Detects privileged role assignments in Azure Resource Manager originating from an unusual city, indicating potential unauthorized elevation of privileges.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - azure
rules_count: 2
---

This detection identifies Azure Activity Logs activity originating from a city that is atypical for the specific event action being performed. The underlying mechanism is a machine learning job, `azure_activitylogs_rare_event_action_for_a_city_ea`, designed to surface anomalous geolocation patterns. The rule is triggered when the anomaly score exceeds 50. Such deviations can indicate compromised credentials used by an attacker operating from a different geography than the authorized user. This activity can be an early indicator of account abuse, potentially preceding broader impact such as data exfiltration or resource exploitation. The rule is designed to be used with Elastic Stack version 9.4.0 and later.

## Attack Chain

1. **Credential Compromise:** An attacker obtains valid Azure credentials (username/password or service principal keys) through phishing, credential stuffing, or other means.
2. **Initial Access:** The attacker uses the compromised credentials to log in to the Azure environment from an unusual geographic location (city).
3. **Activity Log Generation:** The login and subsequent actions generate Azure Activity Logs entries.
4. **Resource Access/Modification:** The attacker performs actions such as adding privileged role assignments, creating virtual machines, modifying network configurations, or accessing Key Vault secrets.
5. **Lateral Movement (Potential):** The attacker may use the initially compromised account to discover and access other resources or accounts within the Azure environment.
6. **Data Exfiltration/Resource Exploitation (Potential):** The attacker exfiltrates sensitive data or uses compromised resources for malicious purposes like cryptocurrency mining.

## Impact

A successful attack can lead to unauthorized access to sensitive data, modification of critical infrastructure, and deployment of malicious resources within the Azure environment. The impact can range from data breaches and financial losses to disruption of services. While the risk score of this detection is low, further investigation is required to determine the extent and nature of the malicious activity.

## Recommendation

*   Enable the associated Machine Learning job (`azure_activitylogs_rare_event_action_for_a_city_ea`) and ensure that the Azure Activity Logs integration is properly configured to provide the necessary data.
*   Review the investigation guide within the rule's `note` field to understand possible investigation steps, including validating user presence in the region and enriching the source IP.
*   Implement response and remediation steps outlined in the rule `note` field such as revoking active sessions, resetting passwords, and reverting changes executed from the unusual city.
*   Configure Conditional Access policies with country allowlists and named egress IP ranges, as recommended in the rule's `note` field, to prevent logins from unexpected locations.
