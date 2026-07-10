---
title: GCP Logging Sink Deletion for Defense Evasion
slug: 2024-01-26-gcp-logging-sink-deletion
description: Detection of Google Cloud Platform (GCP) Logging sink deletion, a technique used by adversaries to impair defenses and evade detection by preventing log entries from being exported to designated destinations.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - gcp
  - logging
  - defense-evasion
vendors:
  - Google
products:
  - Google Cloud Platform
  - Google Cloud Logging
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://cloud.google.com/logging/docs/export
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/008/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: GCP Logging Sink Deletion
    description: Detects deletion of a logging sink in Google Cloud Platform, which can be indicative of defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - gcp
  - title: GCP Logging Sink Deletion - gcloud
    description: Detects deletion of a logging sink in Google Cloud Platform via gcloud command, which can be indicative of defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This threat brief focuses on the detection of a specific defense evasion technique in Google Cloud Platform (GCP): the deletion of Logging sinks. GCP Logging sinks are configured to export log entries to various destinations for analysis and storage. Attackers might delete these sinks to disrupt logging and monitoring, effectively evading detection. The behavior is detected by monitoring GCP audit logs for successful sink deletion events. The deletion action is performed using the Google Cloud Logging API. This activity is of concern to defenders because it directly impacts their ability to identify and respond to malicious activity within their GCP environment.

## Attack Chain

1. An attacker gains unauthorized access to a GCP account with sufficient privileges.
2. The attacker enumerates existing Logging sinks within the target GCP project using `gcloud logging sinks list` or the Cloud Logging API.
3. The attacker identifies a sink to delete, focusing on those critical for security monitoring.
4. The attacker executes a `gcloud logging sinks delete [SINK_NAME]` command or uses the Cloud Logging API to delete the target sink.
5. GCP audit logs record the `google.logging.v*.ConfigServiceV*.DeleteSink` event with an `event.outcome:success`.
6. Log entries that would have been exported to the sink's destination are no longer processed, leading to a gap in security monitoring.
7. The attacker performs other malicious actions within the GCP environment, knowing that their activity is less likely to be detected due to the disabled logging.

## Impact

A successful attack involving Logging sink deletion can severely impact an organization's security posture. The deletion of logging sinks prevents security teams from detecting malicious activities within the GCP environment. This can lead to delayed incident response and increased dwell time for attackers. Depending on the scope of the attack, this could affect multiple projects and services, leading to data breaches or service disruptions.

## Recommendation

*   Deploy the Sigma rule `GCP Logging Sink Deletion` to your SIEM and tune for your environment to detect sink deletion events.
*   Review the audit logs for the specific event.action `google.logging.v*.ConfigServiceV*.DeleteSink` to identify the user or service account responsible for the deletion.
*   Implement additional monitoring and alerting for any future attempts to delete logging sinks, focusing on the specific event action and outcome fields used in the detection query.
