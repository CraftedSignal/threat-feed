---
title: GCP Pub/Sub Topic Deletion for Defense Evasion
slug: 2024-01-29-gcp-pubsub-topic-deletion
description: Detection of Google Cloud Platform Pub/Sub topic deletions can indicate an attempt to disrupt message flow and potentially evade defenses by impairing logging or event-driven automation.
date: "2024-01-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - gcp
  - pubsub
  - defense-evasion
  - cloud
vendors:
  - Google
products:
  - GCP Pub/Sub
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://cloud.google.com/pubsub/docs/overview
rules:
  - title: GCP Pub/Sub Topic Deletion
    description: Detects the deletion of a Pub/Sub topic in Google Cloud Platform.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - cloudtrail
      - gcp
      - pubsub
  - title: GCP Pub/Sub Topic Deletion by Unusual Identity
    description: Detects Pub/Sub topic deletion events performed by identities that do not typically manage Pub/Sub.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - cloudtrail
      - gcp
      - pubsub
rules_count: 2
---

The Google Cloud Platform (GCP) Pub/Sub service facilitates asynchronous messaging between applications. A publisher application creates and sends messages to a topic, and subscriber applications receive those messages. Deleting a Pub/Sub topic can interrupt this communication, potentially disrupting services that rely on the topic for message flow. This action can be exploited by attackers as a defense evasion technique to impair logging or event-driven automation. This rule identifies the deletion of a topic in Google Cloud Platform (GCP) by monitoring audit logs for `google.pubsub.v*.Publisher.DeleteTopic` events. Defenders should investigate unexpected topic deletions, as they might indicate malicious activity or unauthorized access. The activity is logged in GCP audit logs, and can be accessed via the GCP Fleet integration or Filebeat module.

## Attack Chain

1.  An attacker gains unauthorized access to a GCP account with sufficient permissions to manage Pub/Sub topics.
2.  The attacker enumerates existing Pub/Sub topics to identify a target for deletion.
3.  The attacker executes the `google.pubsub.v*.Publisher.DeleteTopic` API call to delete the target topic.
4.  The GCP audit logs record the successful topic deletion event with event.action:google.pubsub.v*.Publisher.DeleteTopic and event.outcome:success.
5.  Applications that publish to or subscribe from the deleted topic experience disruptions in message flow.
6.  Logging or event-driven automation that relies on the deleted topic is impaired, potentially hindering incident response or security monitoring.

## Impact

Successful deletion of a Pub/Sub topic can disrupt critical services and impair defenses, leading to delayed incident response and reduced visibility into malicious activities. The impact is service disruption, data loss, and potential concealment of malicious activities. The severity is low, as the deletion itself does not directly compromise data but hinders visibility.

## Recommendation

*   Deploy the Sigma rule `GCP Pub/Sub Topic Deletion` to your SIEM to detect unauthorized topic deletions by monitoring GCP audit logs.
*   Review the audit logs for the specific `event.action: google.pubsub.v*.Publisher.DeleteTopic` to identify the exact time and user or service account responsible for the deletion, as described in the overview.
*   Implement stricter access controls and permissions for Pub/Sub topics to prevent unauthorized deletions in the future.
*   Monitor GCP audit logs for any related activities or anomalies around the same timeframe to identify potential malicious intent or unauthorized access.
