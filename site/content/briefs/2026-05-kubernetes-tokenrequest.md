---
title: Kubernetes Service Account Token Created via TokenRequest API by Non-System Identity
slug: 2026-05-kubernetes-tokenrequest
description: The rule detects the creation of Kubernetes service account tokens through the TokenRequest API by non-system identities, which can be abused to escalate privileges, pivot to cloud resources, or generate persistent tokens, bypassing file system-based detection.
date: "2026-05-12T08:17:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - credential-access
  - tokenrequest
  - cloud
vendors:
  - Elastic
products:
  - kubernetes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-v1/
  - https://attack.mitre.org/techniques/T1552/007/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/credential_access_kubernetes_service_account_token_created_via_tokenrequest.toml
rules:
  - title: Kubernetes TokenRequest API Token Creation by Non-System Account
    description: Detects the creation of a Kubernetes service account token through the TokenRequest API by a non-system identity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - auditd
      - kubernetes
  - title: Kubernetes TokenRequest API Request URI Analysis
    description: Detects suspicious TokenRequest API calls by analyzing the request URI for non-standard namespaces or service accounts.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - auditd
      - kubernetes
rules_count: 2
---

This detection rule identifies the creation of Kubernetes service account tokens through the TokenRequest API by non-system identities. The TokenRequest API enables programmatic generation of short-lived tokens for service accounts, circumventing filesystem access or mounted projected tokens. Attackers gaining initial cluster access can exploit this API to mint tokens for highly privileged service accounts, enabling lateral movement to cloud provider resources (IRSA/workload identity) or creating persistent tokens. Unlike mounted service account tokens detectable via filesystem monitoring, tokens created via TokenRequest API lack a filesystem footprint, appearing solely in Kubernetes audit logs as a 'create' verb on the 'serviceaccounts/token' subresource. The rule excludes legitimate system components (kubelet, kube-controller-manager, cloud provider managed identities such as EKS, AKS, and GKE) that create tokens for pod lifecycle management.

## Attack Chain

1.  Attacker gains initial access to a Kubernetes cluster, potentially through compromised credentials or a vulnerable application.
2.  The attacker identifies a target service account with elevated privileges or access to cloud resources via IRSA.
3.  The attacker uses the Kubernetes TokenRequest API to request a new token for the target service account. The request specifies the service account's namespace and name.
4.  Kubernetes API server validates the request and confirms the attacker's identity has permissions to create tokens for the target service account.
5.  If authorized, the API server generates a new service account token. The creation event is logged in the Kubernetes audit logs with the `create` verb on the `serviceaccounts/token` subresource.
6.  The attacker receives the generated token, which has a limited lifespan.
7.  The attacker uses the newly acquired service account token to authenticate to the Kubernetes API server, cloud provider APIs, or other services, impersonating the target service account.
8.  The attacker performs privileged actions or accesses sensitive data, leveraging the permissions associated with the target service account.

## Impact

Successful exploitation allows attackers to escalate privileges within the Kubernetes cluster and potentially pivot to cloud provider resources. By minting tokens for service accounts linked to IAM roles (IRSA in AWS, workload identity in Azure and GCP), attackers can gain unauthorized access to cloud services, potentially leading to data breaches, resource hijacking, and service disruption. This can affect any organization using Kubernetes, especially those relying on cloud-managed Kubernetes services.

## Recommendation

*   Deploy the Sigma rule `Kubernetes TokenRequest API Token Creation by Non-System Account` to your SIEM and tune for your environment.
*   Review RBAC permissions to restrict `create` access to `serviceaccounts/token` subresource only to legitimate system components.
*   Monitor Kubernetes audit logs for `create` operations on `serviceaccounts/token` resources, focusing on unusual source IPs or user agents as highlighted by the Sigma rule above.
*   Investigate and rotate affected service account credentials if unauthorized token creation is detected, especially for IRSA-linked service accounts.
