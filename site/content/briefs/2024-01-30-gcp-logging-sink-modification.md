---
title: GCP Logging Sink Modification for Exfiltration or Defense Evasion
slug: 2024-01-30-gcp-logging-sink-modification
description: Modification of a Google Cloud Platform (GCP) Logging sink is detected, potentially indicating an adversary's attempt to exfiltrate logs to an unauthorized destination or impair defenses by disabling or modifying cloud logs.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - gcp
  - cloud
  - exfiltration
  - defense_evasion
vendors:
  - Google
products:
  - Google Cloud Platform
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://cloud.google.com/logging/docs/export#how_sinks_work
  - https://attack.mitre.org/techniques/T1537/
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: GCP Logging Sink Modification
    description: Detects modifications to GCP Logging sinks, potentially indicating unauthorized data exfiltration or defense evasion.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - exfiltration
    techniques:
      - T1537
      - T1562.008
    data_sources:
      - cloudtrail
      - gcp
  - title: GCP Logging Sink Destination Changed
    description: Detects changes to the destination of a GCP Logging sink.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - gcp
rules_count: 2
---

This detection identifies modifications to Logging sinks within Google Cloud Platform (GCP). Logging sinks are a mechanism to export copies of log entries to destinations like Cloud Storage buckets, BigQuery datasets, or Pub/Sub topics. An attacker might modify a sink's configuration to redirect logs to a destination under their control for exfiltration, or to disable logging entirely to evade detection. This activity is identified by monitoring GCP audit logs for `UpdateSink` events. The rule is triggered by successful sink modifications. This matters because it can lead to data breaches or hide malicious activity.

## Attack Chain

1. An attacker gains access to a GCP account with sufficient privileges to modify Logging sinks. This could be through compromised credentials, IAM misconfigurations, or exploiting vulnerabilities in applications with access to GCP resources.
2. The attacker enumerates existing Logging sinks using the `gcloud logging sinks list` command or the Cloud Logging API to identify a suitable target.
3. The attacker modifies the target Logging sink's destination to a resource under their control, such as a Cloud Storage bucket in a different project or a Pub/Sub topic they subscribe to. They use the `gcloud logging sinks update` command or the Cloud Logging API.
4. The attacker may also modify the filter associated with the sink to capture a specific subset of logs, focusing on sensitive data or logs related to their activities.
5. Once the sink is updated, logs matching the sink's filter are now routed to the attacker-controlled destination.
6. The attacker accesses the exfiltrated logs from their destination, potentially revealing sensitive information.
7. Alternatively, the attacker modifies the logging sink to disable it entirely, preventing security teams from detecting malicious activity.
8. The attacker covers their tracks by deleting or modifying audit logs related to the sink modification, if possible.

## Impact

A successful Logging sink modification can lead to the exfiltration of sensitive data, including personally identifiable information (PII), financial records, or proprietary business data. This can result in financial loss, reputational damage, and legal liabilities. Furthermore, disabling or modifying cloud logs can impair an organization's ability to detect and respond to security incidents, potentially prolonging the duration and increasing the impact of an attack.

## Recommendation

*   Deploy the Sigma rule "GCP Logging Sink Modification" to your SIEM and tune for your environment. This rule detects modifications to Logging sinks (rule).
*   Review the event details for the specific `event.action` field value `google.logging.v*.ConfigServiceV*.UpdateSink` to confirm the type of modification made to the logging sink.
*   Implement additional monitoring and alerting for changes to logging sink configurations to detect similar unauthorized modifications in the future (content).
*   Review and strengthen access controls and permissions related to logging sink configurations to prevent unauthorized modifications, ensuring that only authorized personnel have the necessary permissions (content).
*   Reference the MITRE ATT&CK techniques T1537 (Transfer Data to Cloud Account) and T1562.008 (Disable or Modify Cloud Logs) to understand the broader context of this threat (ttps).
