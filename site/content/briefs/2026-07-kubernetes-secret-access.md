---
title: Kubernetes Secret Access by Node or Pod Service Account
slug: 2026-07-kubernetes-secret-access
description: Attackers who have compromised a Kubernetes pod or node are observed attempting to `get` or `list` Kubernetes Secret objects via the API, a common post-compromise technique by various threat actors to achieve credential access and gather sensitive information such as tokens, registry credentials, TLS keys, or application configurations.
date: "2026-07-06T09:44:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - credential-access
  - cloud-security
  - container-security
  - threat-detection
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers who stole a pod service-account token or node credentials sweep Secret objects for tokens, registry credentials, TLS keys, or application configuration.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/credential_access_kubernetes_secret_read_by_node_or_pod_service_account.toml
  - https://attack.mitre.org/techniques/T1552/007/
  - https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens
rules:
  - title: Kubernetes Secret Get or List from Node or Pod Service Account
    description: Detects attempts by Kubernetes node credentials (system:node:*) or pod service accounts (system:serviceaccount:*) to 'get' or 'list' Kubernetes Secret objects via the API. This often indicates credential access post-compromise.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - cloud_audit
      - kubernetes
rules_count: 1
---

This brief details a common post-exploitation technique where attackers, having successfully gained control of a Kubernetes node or compromised a pod, proceed to enumerate and extract sensitive information stored in Kubernetes Secret objects. This activity, detectable through Kubernetes audit logs, involves making `get` or `list` API calls against the `secrets` resource from credentials associated with a node (`system:node:*`) or a pod service account (`system:serviceaccount:*`). Such actions are highly suspicious, as legitimate kubelet and service account operations typically involve tightly scoped API usage and rarely require broad secret enumeration. Attackers leverage this behavior to sweep for critical credentials (e.g., API tokens, registry credentials, TLS certificates, application configurations) that can facilitate lateral movement, privilege escalation, or further data exfiltration within the cluster or connected environments. Even failed attempts to access secrets are indicative of attacker intent and should be investigated.

## Attack Chain

1.  **Initial Compromise**: Attacker gains unauthorized access to a Kubernetes pod or node, often via a vulnerable application, exposed administrative interface, or container escape.
2.  **Credential Acquisition**: From the compromised context, the attacker obtains or utilizes the inherent `system:serviceaccount` token of the pod or `system:node` credentials of the node.
3.  **Command Execution**: Using the acquired credentials, the attacker executes arbitrary commands or makes API requests from the compromised pod or node.
4.  **Credential Access / Discovery**: The attacker issues `get` or `list` API calls against the Kubernetes `secrets` resource to identify available secrets.
5.  **Data Exfiltration**: The attacker successfully retrieves the content of accessible secrets, including sensitive data like API tokens, private keys, database credentials, or image registry credentials.
6.  **Impact**: The attacker leverages the exfiltrated secrets for lateral movement within the Kubernetes cluster, privilege escalation, access to external systems, or further data collection.

## Impact

Successful exploitation of this technique can lead to significant compromise of the Kubernetes cluster and its hosted applications. Attackers can steal critical API tokens, database credentials, TLS keys, and sensitive application configurations, enabling them to move laterally across namespaces, escalate privileges, access and modify application data, or deploy malicious workloads. This can result in data breaches, disruption of services, and unauthorized control over cloud resources. While no specific victim counts are provided, the technique is broadly applicable to any Kubernetes environment.

## Recommendation

*   Deploy the Sigma rule "Kubernetes Secret Get or List from Node or Pod Service Account" included in this brief to your SIEM and tune for your environment.
*   Ensure comprehensive Kubernetes audit logging is enabled and ingested into your security monitoring platform to activate the rule above.
*   Review the `User.Username` (or `kubernetes.audit.user.username`) field in logs when this rule triggers to identify the specific node or service account involved and investigate its Role-Based Access Control (RBAC) scope.
*   Inspect `kubernetes.audit.objectRef.namespace`, `kubernetes.audit.objectRef.name`, `source.ip`, and `user_agent.original` fields for anomalous activity compared to known legitimate controllers.
*   Baseline known service accounts, namespaces, or user agents that legitimately list or get Secrets, as noted in the `falsepositives` section of the Sigma rule, and create exclusions.
*   If malicious activity is confirmed, immediately revoke the compromised token or node credentials, cordon or isolate the affected host or workload, rotate any exposed secrets, and tighten RBAC to enforce least privilege for all identities.
