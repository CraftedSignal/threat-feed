---
title: Kubernetes Admission Webhook Created or Modified by Non-System Identity
slug: 2026-06-kubernetes-admission-webhook
description: The creation, modification, or deletion of Kubernetes MutatingWebhookConfigurations or ValidatingWebhookConfigurations by non-system identities can allow attackers to inject malicious sidecars or block security tooling deployments for persistence and defense evasion.
date: "2026-06-01T10:10:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - persistence
  - defense_evasion
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/persistence_kubernetes_admission_webhook_created_or_modified.toml
rules:
  - title: Kubernetes Admission Webhook Created or Modified by Non-System Identity
    description: Detects creation, modification, or deletion of Kubernetes MutatingWebhookConfigurations or ValidatingWebhookConfigurations by non-system identities.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1546
      - T1562
    data_sources:
      - process_creation
      - linux
  - title: Kubernetes Malicious Webhook Configuration URL
    description: Detects a suspicious external URL in a Kubernetes webhook configuration.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1546
      - T1562
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Admission webhooks in Kubernetes are a powerful mechanism that intercepts API requests before they are persisted, allowing for mutation or validation of resources. This capability can be abused by attackers to establish persistence and evade defenses. By creating, modifying, or deleting MutatingWebhookConfigurations or ValidatingWebhookConfigurations, an attacker can inject malicious sidecars into pods, block the deployment of security tools, or exfiltrate pod specifications. This technique is stealthy because the webhook configuration itself may appear benign while actively manipulating Kubernetes API traffic. The Elastic detection rule released on 2026-05-05, and updated on 2026-05-26, aims to detect such malicious activity by monitoring changes to admission webhooks by non-system identities.

## Attack Chain

1.  An attacker gains unauthorized access to a Kubernetes cluster, potentially through compromised credentials or a vulnerability in a cluster component.
2.  The attacker identifies existing MutatingWebhookConfigurations or ValidatingWebhookConfigurations, or determines the need to create new ones to achieve their objectives.
3.  The attacker crafts a malicious webhook configuration targeting specific resources and operations, such as pod creation or updates.
4.  The malicious webhook configuration is applied to the cluster, potentially using `kubectl apply -f malicious-webhook.yaml`. This action is logged as a `create`, `update`, or `patch` event on `mutatingwebhookconfigurations` or `validatingwebhookconfigurations`.
5.  The attacker modifies the webhook to inject malicious sidecars into new pods, altering their behavior without directly modifying the pod specifications.
6.  Alternatively, the attacker configures the webhook to block the deployment of security tools by validating pod specifications and rejecting those that match certain criteria.
7.  The attacker leverages the malicious webhook for persistence, ensuring that their injected sidecars or blocked deployments remain effective even after pod restarts or cluster updates.
8.  The attacker may exfiltrate pod specifications to an external server using the malicious webhook.

## Impact

Successful manipulation of Kubernetes admission webhooks can lead to a variety of detrimental outcomes. Attackers can compromise workloads by injecting malicious code into pods, evade security controls by blocking the deployment of defensive tools, and establish persistent access to the cluster. The scope of impact depends on the targeted resources and operations defined in the malicious webhook configuration. If webhooks are used to target pod creation, all newly created pods within the targeted namespaces could be affected.

## Recommendation

*   Deploy the Sigma rule `Kubernetes Admission Webhook Created or Modified by Non-System Identity` to your SIEM to detect unauthorized modifications to admission webhooks.
*   Review Kubernetes audit logs for `create`, `update`, `patch`, or `delete` events on `mutatingwebhookconfigurations` or `validatingwebhookconfigurations` resources, focusing on non-system identities as defined in the Sigma rule.
*   Monitor the `kubernetes.audit.requestObject.webhooks.clientConfig.url` for suspicious external URLs in audit logs, as described in the overview, which may indicate data exfiltration.
*   Enable Kubernetes audit logging to capture the necessary events for the Sigma rules to function effectively.
