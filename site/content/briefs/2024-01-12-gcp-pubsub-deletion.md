---
title: GCP Pub/Sub Subscription Deletion
slug: 2024-01-12-gcp-pubsub-deletion
description: Detection of a Google Cloud Platform Pub/Sub subscription deletion, which can be used by adversaries to disrupt communication, evade detection, or impair defenses.
date: "2024-01-12T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - gcp
  - pubsub
  - defense_evasion
  - cloud
vendors:
  - Google
products:
  - Pub/Sub
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
  - title: GCP Pub/Sub Subscription Deletion
    description: Detects the deletion of a Pub/Sub subscription in Google Cloud Platform, which could indicate defense evasion or service disruption.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1489
      - T1562
    data_sources:
      - cloudtrail
      - gcp
  - title: GCP Pub/Sub Subscription Deletion by Unusual Principal
    description: Detects Pub/Sub subscription deletions performed by principals not typically associated with such actions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1489
      - T1562
    data_sources:
      - cloudtrail
      - gcp
rules_count: 2
---

This rule detects the deletion of a subscription within Google Cloud Platform's (GCP) Pub/Sub service. GCP Pub/Sub is a messaging service that facilitates asynchronous communication between services. A subscription represents the stream of messages delivered to subscribing applications. An attacker may delete a Pub/Sub subscription as a form of defense evasion, to disrupt the flow of information, or as part of a broader attack aimed at impairing the target's infrastructure. The rule focuses on identifying successful subscription deletions logged in GCP audit logs and helps defenders identify potentially malicious activity targeting GCP environments. The original rule was created on 2020/09/23 and updated on 2026/04/10.

## Attack Chain

1.  The attacker gains access to a GCP account or service account with sufficient privileges to manage Pub/Sub subscriptions.
2.  The attacker authenticates to the GCP environment using stolen credentials or a compromised service account.
3.  The attacker identifies a target Pub/Sub subscription that is critical for application communication or monitoring.
4.  The attacker executes the `google.pubsub.v*.Subscriber.DeleteSubscription` API call to delete the targeted subscription.
5.  GCP audit logs record the successful deletion of the subscription with `event.outcome:success`.
6.  The deletion disrupts message delivery to the subscribing application, potentially causing service disruptions or data loss.
7.  The attacker may delete multiple subscriptions to maximize impact and hinder incident response efforts.

## Impact

A successful subscription deletion can lead to disruption of services relying on Pub/Sub for asynchronous communication. While the severity is rated as "low," the impact can be significant if critical services are affected. The potential for data loss and operational disruption exists, especially if the deleted subscription is not immediately restored. The number of affected victims or sectors is dependent on the targeted subscriptions and applications within the GCP environment.

## Recommendation

*   Deploy the Sigma rule `GCP Pub/Sub Subscription Deletion` to your SIEM to detect unauthorized subscription deletions.
*   Review the audit logs for the specific `event.action: google.pubsub.v*.Subscriber.DeleteSubscription` to identify the user or service account responsible for the deletion.
*   Implement additional access controls and monitoring for Pub/Sub resources to prevent unauthorized deletions in the future.
*   Ensure that the GCP Fleet integration, Filebeat module, or similarly structured data is configured to collect relevant GCP audit logs.
*   Investigate any alerts triggered by the Sigma rule, following the investigation steps outlined in the rule's note field.
