---
title: Kubernetes Admission Webhook Manipulation for Persistence and Defense Evasion
slug: 2024-01-kubernetes-admission-webhook-modified
description: The rule detects creation, modification, or deletion of Kubernetes MutatingWebhookConfigurations or ValidatingWebhookConfigurations by non-system identities, allowing attackers to inject malicious sidecars, block security tooling, or exfiltrate pod specifications.
date: "2024-01-03T18:22:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - persistence
  - defense-evasion
vendors:
  - Elastic
products:
  - kubernetes
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
  - title: Kubernetes Admission Webhook Modified - Non-System User
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
      - audit
      - kubernetes
  - title: Kubernetes Admission Webhook ClientConfig External URL
    description: Detects creation or modification of Kubernetes admission webhooks with a clientConfig URL pointing to the public internet, which could indicate data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - persistence
    techniques:
      - T1041
      - T1546
    data_sources:
      - audit
      - kubernetes
rules_count: 2
---

Kubernetes admission webhooks provide a powerful mechanism to intercept and modify API requests before they are persisted.  Attackers can abuse this functionality by creating or modifying MutatingWebhookConfigurations or ValidatingWebhookConfigurations to achieve persistence and defense evasion. The Elastic detection rule identifies unauthorized changes to these webhooks by non-system identities. Successful exploitation can allow attackers to inject malicious sidecars into pods, block the deployment of security tools, or exfiltrate sensitive pod specifications.  This technique is particularly stealthy as the webhook configuration itself may appear benign, while actively modifying or intercepting Kubernetes API traffic. The rule focuses on changes to webhook configurations within Kubernetes environments.

## Attack Chain

1. An attacker gains initial access to a Kubernetes cluster, potentially through compromised credentials or a vulnerability in a cluster-exposed service.
2. The attacker authenticates to the Kubernetes API server using their compromised or obtained credentials.
3. The attacker crafts a malicious MutatingWebhookConfiguration or ValidatingWebhookConfiguration.
4. The attacker creates, updates, or patches the webhook configuration using `kubectl` or similar API interaction tools, evading standard system account usage patterns.
5. The malicious webhook intercepts API requests matching its defined rules (e.g., pod creation).
6. If a mutating webhook, it injects a malicious sidecar container into new pods or modifies pod securityContext. If validating, it blocks deployment of security tooling.
7. The injected sidecar executes attacker-controlled code within the pod's environment or the blocked security tooling prevents detection.
8. The attacker maintains persistent access to the cluster and potentially exfiltrates data or disrupts services.

## Impact

Compromising admission webhooks can have a significant impact on a Kubernetes environment.  Attackers can use this technique to inject malicious code into every new pod, effectively compromising all applications running in the cluster. They can also block the deployment of security tools, preventing detection and remediation. The rule's description mentions that the technique allows attackers to exfiltrate pod specifications; in clusters with many secrets mounted as environment variables, this could lead to significant data loss.  The severity of this attack is medium, with a risk score of 47 according to the source.

## Recommendation

*   Deploy the Sigma rule "Kubernetes Admission Webhook Created or Modified" to your SIEM and tune the `user.name` and `kubernetes.audit.objectRef.name` filters for your environment to reduce false positives.
*   Monitor Kubernetes audit logs (`logs-kubernetes.audit_logs-*`) for unauthorized modifications to MutatingWebhookConfiguration and ValidatingWebhookConfiguration resources.
*   Inspect `kubernetes.audit.requestObject.webhooks.clientConfig.url` for suspicious external URLs, and validate `kubernetes.audit.requestObject.webhooks.clientConfig.service.*` to ensure in-cluster services are legitimate.
*   Implement strict RBAC policies to limit which users and service accounts can create or modify admission webhooks.
*   Regularly review existing admission webhooks for unexpected configurations, focusing on `failurePolicy`, `namespaceSelector`, `objectSelector`, `rules.operations`, and `rules.resources`.
