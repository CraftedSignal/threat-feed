---
title: Kubernetes Admission Controller Modification
slug: 2024-11-kubernetes-admission-controller-modification
description: An adversary modifies Kubernetes admission controller configurations to achieve persistence, escalate privileges, or gain unauthorized access to credentials within the cluster.
date: "2024-11-01T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - admission-controller
  - privilege-escalation
  - persistence
  - credential-access
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
  - https://security.padok.fr/en/blog/kubernetes-webhook-attackers
  - https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_change_admission_controller.yml
rules:
  - title: Kubernetes Admission Controller Created
    description: Detects creation of Kubernetes Admission Controller configuration.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1552.007
    data_sources:
      - kubernetes
      - audit
  - title: Kubernetes Admission Controller Modified
    description: Detects modification of Kubernetes Admission Controller configuration.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1552.007
    data_sources:
      - kubernetes
      - audit
rules_count: 2
---

The Kubernetes admission controller is a crucial component that governs API requests to a Kubernetes cluster. Attackers can modify mutating or validating webhook configurations to intercept and manipulate these requests. By creating, updating, or replacing these configurations, adversaries can inject malicious code, alter resource definitions, or even exfiltrate sensitive information like access credentials. This activity can lead to privilege escalation, persistence within the cluster, and ultimately, a compromise of the entire Kubernetes environment. The attacks are typically stealthy as they operate within the legitimate Kubernetes API framework, making detection challenging. This behavior is particularly concerning for organizations relying on Kubernetes for critical applications and sensitive data.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the Kubernetes cluster, potentially through compromised credentials or a vulnerability in a deployed application.
2.  **Discovery:** The attacker enumerates existing admission controller configurations (mutatingwebhookconfigurations and validatingwebhookconfigurations) to identify potential targets.
3.  **Configuration Modification:** The attacker uses `kubectl` or the Kubernetes API to create, update, or replace a webhook configuration. This involves crafting a malicious webhook that will intercept API requests.
4.  **Webhook Deployment:** The malicious webhook is deployed as a service within the Kubernetes cluster.
5.  **API Interception:** When a user or application makes an API request that matches the webhook's defined rules, the webhook intercepts the request.
6.  **Malicious Code Injection:** The webhook injects malicious code or alters the API request to achieve the attacker's objectives (e.g., granting unauthorized permissions, modifying resource configurations).
7.  **Persistence/Privilege Escalation/Credential Access:** Depending on the injected code, the attacker achieves persistence by ensuring malicious code is always present, escalates privileges by modifying role bindings, or accesses credentials by intercepting secret creation requests.
8.  **Lateral Movement/Data Exfiltration:** The attacker leverages their gained access to move laterally within the cluster or exfiltrate sensitive data.

## Impact

Successful modification of Kubernetes admission controllers can have severe consequences. This can result in unauthorized access to sensitive data, complete cluster compromise, and denial of service. The impact ranges from data breaches and service disruptions to long-term persistence within the environment, allowing attackers to maintain control over the cluster. The stealthy nature of this attack makes it difficult to detect, potentially allowing attackers to operate undetected for extended periods.

## Recommendation

*   Deploy the Sigma rule "Kubernetes Admission Controller Modification" to your SIEM and tune it for your environment to detect suspicious modifications to webhook configurations (logsource: kubernetes, service: audit).
*   Monitor Kubernetes audit logs for `create`, `delete`, `patch`, `replace`, and `update` verbs on `mutatingwebhookconfigurations` and `validatingwebhookconfigurations` resources (logsource: kubernetes, service: audit).
*   Implement strong RBAC policies to limit access to Kubernetes API resources and prevent unauthorized modification of admission controller configurations.
*   Regularly review and audit existing admission controller configurations to identify any unexpected or malicious webhooks.
