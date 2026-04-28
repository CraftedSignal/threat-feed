---
title: Malicious Azure Kubernetes Admission Controller Configuration
slug: 2024-01-azure-kubernetes-admission-controller
description: An adversary can exploit Kubernetes Admission Controllers in Azure to achieve persistence, privilege escalation, or credential access by manipulating webhook configurations.
date: "2024-01-03T15:30:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - kubernetes
  - admission-controller
  - persistence
  - privilege-escalation
  - credential-access
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain Policy Modification
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
rules:
  - title: Azure Kubernetes Admission Controller Configuration Change
    description: Detects creation or modification of MutatingWebhookConfigurations or ValidatingWebhookConfigurations in Azure Kubernetes Service.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
      - T1552
      - T1552.007
    data_sources:
      - azure
      - activitylogs
  - title: Azure Kubernetes Admission Controller List
    description: Detects listing of Admission Controllers in Azure Kubernetes Service.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

Kubernetes Admission Controllers are critical components that intercept and potentially modify requests to the Kubernetes API server. These controllers rely on admission webhooks (MutatingAdmissionWebhook or ValidatingAdmissionWebhook) deployed within the cluster. A malicious actor can abuse these webhooks to establish persistence by modifying pod creation operations and injecting malicious containers into new pods via MutatingAdmissionWebhook. Alternatively, ValidatingAdmissionWebhook can be used to intercept API server requests, potentially exposing secrets and sensitive information. This activity allows for credential access and privilege escalation, impacting the overall security posture of the Kubernetes cluster.

## Attack Chain

1.  The attacker gains initial access to the Azure Kubernetes cluster, possibly through compromised credentials or a vulnerability in a deployed application.
2.  The attacker identifies the existing Admission Controller configuration within the Kubernetes cluster.
3.  The attacker crafts a malicious MutatingAdmissionWebhook configuration to intercept pod creation requests.
4.  The malicious webhook is deployed to the cluster, configured to modify pod specifications.
5.  When new pods are created, the webhook injects a malicious container into the pod specification before deployment.
6.  The malicious container executes within the newly created pod, providing the attacker with persistent access to the cluster.
7.  Alternatively, the attacker crafts a malicious ValidatingAdmissionWebhook to intercept API requests.
8.  The webhook captures sensitive data, such as secrets, and sends it to an attacker-controlled server, resulting in credential access.

## Impact

Compromising the Kubernetes Admission Controller can lead to persistent access within the cluster. The attacker can inject malicious containers into numerous pods, potentially affecting all applications deployed in the cluster. Sensitive information, like secrets, can be stolen, enabling lateral movement and privilege escalation within the Azure environment. The impact ranges from data breaches to complete cluster compromise.

## Recommendation

*   Deploy the Sigma rule "Azure Kubernetes Admission Controller Configuration Change" to detect unauthorized modifications to Admission Controller configurations in Azure Activity Logs.
*   Regularly review and audit existing Admission Controller configurations for any unexpected or malicious webhooks.
*   Implement strong RBAC policies to restrict access to Admission Controller configuration and prevent unauthorized modifications.
*   Monitor Azure Activity Logs for `MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/ADMISSIONREGISTRATION.K8S.IO` and `MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/ADMISSIONREGISTRATION.K8S.IO` operations to identify potential abuse.
