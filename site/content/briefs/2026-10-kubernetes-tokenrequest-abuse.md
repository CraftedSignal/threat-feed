---
title: Abuse of Kubernetes TokenRequest API for Credential Access
slug: 2026-10-kubernetes-tokenrequest-abuse
description: Attackers with initial cluster access are abusing the Kubernetes TokenRequest API to mint arbitrary service account tokens, facilitating privilege escalation, cloud resource pivoting, and persistence without leaving filesystem artifacts.
date: "2026-10-07T16:36:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - kubernetes
  - cloud-security
  - audit-logs
vendors:
  - Amazon
  - Microsoft
  - Google
  - Kubernetes
products:
  - Elastic Kubernetes Service (EKS)
  - Azure Kubernetes Service (AKS)
  - Google Kubernetes Engine (GKE)
  - Kubernetes (all versions)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers who have gained initial access to a cluster can abuse this API to mint tokens for more privileged service accounts.
    confidence_band: high
references:
  - https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/
  - https://attack.mitre.org/techniques/T1552/007/
rules:
  - title: Detect Kubernetes Service Account Token Created via TokenRequest API
    description: Detects the creation of a Kubernetes service account token through the TokenRequest API by a non-system identity to identify potential credential harvesting or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides KQL-based detection logic.
  enrichment_needed:
    - item: Authorized service account list
      owner: SOC
      reason: To reduce false positives for platform-specific service accounts.
      evidence: False positive section of the brief.
  hunt_leads:
    - lead: Search for 'create' verbs against 'serviceaccounts/token' subresource.
      technique_id: T1552.007
      data_needed:
        - Kubernetes Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rule description specifies audit log visibility.
  mitigation_plan:
    - priority: short_term
      action: Review and audit RBAC roles granting 'create' permissions on serviceaccount tokens.
      owner: IT Operations
      addresses: Excessive RBAC permissions.
      evidence: Triage and analysis section of the source.
  gaps:
    - Lack of visibility if Kubernetes audit logs are not configured.
---

The Kubernetes TokenRequest API allows users and workloads to programmatically generate short-lived tokens for any service account they have create permissions on. Threat actors who have gained initial access to a cluster are abusing this API to mint tokens for highly privileged service accounts. This technique is particularly dangerous because, unlike traditional mounted service account tokens that rely on file access, TokenRequest tokens leave no filesystem footprint and are exclusively visible within Kubernetes audit logs via a create verb on the serviceaccounts/token subresource. Attackers leverage these tokens to pivot to cloud provider resources via IAM Roles for Service Accounts (IRSA) or other workload identity mechanisms, or to maintain persistence that survives pod termination. This behavior was documented as an emerging threat vector in Kubernetes environments, including managed services like EKS, AKS, and GKE.

## Attack Chain

1. Attacker gains initial access to a containerized application within the Kubernetes cluster.
2. Attacker probes the cluster for RBAC permissions, specifically looking for 'create' authority on serviceaccounts/token.
3. Attacker identifies a high-privileged service account within the target or privileged namespaces.
4. Attacker invokes the TokenRequest API, targeting the chosen service account to mint a new token.
5. The API server validates the request and issues the short-lived bearer token directly to the attacker.
6. Attacker exfiltrates the generated token or uses it immediately to authenticate against the K8s API or external cloud provider APIs.
7. Attacker performs secondary actions, such as resource exfiltration, lateral movement, or persistence, using the minted identity.

## Impact

Successful abuse of the TokenRequest API results in unauthorized privilege escalation, potential access to cloud provider resources linked to Kubernetes service accounts, and long-term persistence in the cluster. This threat impacts multi-tenant and cloud-hosted Kubernetes environments, allowing an attacker to operate with the permissions of a compromised service account without triggering file-integrity monitoring systems that typically guard against credential theft.

## Recommendation

Detection engineering teams should prioritize the implementation of audit-based monitoring for API requests. 
- Deploy the provided Sigma rule to monitor for suspicious TokenRequest API activity in Kubernetes audit logs.
- Review RBAC ClusterRoleBindings to identify identities possessing excessive permissions to the 'create' subresource on service accounts.
- Establish alerting for unauthorized user-agents or source IPs interacting with the TokenRequest API.
- Ensure that Kubernetes audit logs are being ingested into a centralized SIEM for timely detection of create verbs on serviceaccounts/token.
