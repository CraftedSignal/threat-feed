---
brief_id: brief-2026-10-21-eks-tokenrequest-abuse
event_id: brief-2026-10-21-eks-tokenrequest-abuse
revision: 5
activity_at: "2026-10-21T09:08:08Z"
revision_history:
  - revision: 2
    at: "2026-10-21T08:31:51Z"
    checksum: sha256:1058b692c253467463df054c5e0d4f4113a83a0cab087fe34de63b84020afb71
    summary: added coverage for Elastic Kubernetes Service (EKS)
    changed_fields:
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_endpoint_permission_enumeration_by_anonymous_user_aws_eks.toml
  - revision: 3
    at: "2026-10-21T08:31:52Z"
    checksum: sha256:bc7b33d106b43e85e3b18fe69a2e84db217962088ce6066b70edb0650429db74
    summary: added coverage for Elastic Kubernetes Service (EKS)
    changed_fields:
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_kubernetes_multi_resource_setup_recon_aws_eks.toml
  - revision: 4
    at: "2026-10-21T08:31:53Z"
    checksum: sha256:2d6f8dced2690306ac3dfe31a6642e92903386e8874d19189f2a3fe88719af78
    summary: added coverage for Elastic Kubernetes Service (EKS)
    changed_fields:
      - lastmod
      - references
      - severity
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/execution_kubernetes_pod_exec_curl_wget_https_aws_eks.toml
  - revision: 5
    at: "2026-10-21T09:08:08Z"
    checksum: sha256:2bf2ab474fcc44d25ac21109649aaee680ca04b651666f07f6ba3813098e2f7a
    summary: 'added detection rule: Detect Authorized Anonymous Requests to EKS API'
    changed_fields:
      - lastmod
      - references
      - rules
      - tags
      - ttps
      - updates
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/initial_access_anonymous_request_authorized_aws_eks.toml
title: 'Amazon EKS: Improper TokenRequest API usage detection'
slug: 2026-10-eks-tokenrequest-abuse
description: Attackers can abuse the Kubernetes TokenRequest API to mint service account tokens without filesystem access, facilitating privilege escalation and movement to cloud resources via IAM Roles for Service Accounts (IRSA).
date: "2026-10-21T07:47:08Z"
lastmod: "2026-10-21T09:06:51Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - cloud
  - kubernetes
  - aws
  - eks
  - credential-access
  - reconnaissance
  - discovery
  - execution
  - command-and-control
  - cloud-security
  - initial-access
vendors:
  - Amazon
products:
  - Elastic Kubernetes Service (EKS)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.007
    subtechnique_name: Container API
    evidence: Attackers who have gained initial access to a cluster can abuse this API to mint tokens for more privileged service accounts.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: This rule detects potential endpoint enumeration attempts by an anonymous user.
    confidence_band: high
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
    subtechnique_id: T1595.003
    subtechnique_name: Wordlist Scanning
    evidence: This detects a burst of Kubernetes API requests from an unauthenticated identity that probes many different endpoints and resource types.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: Detects pod or attach exec API calls where the decoded request query implies curl or wget fetching an https URL.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Attackers with permission to exec into workloads often run one-liners to stage tooling, pull scripts or binaries, or exfiltrate data over HTTPS.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.001
    subtechnique_name: Default Accounts
    evidence: Attackers may attempt to use anonymous accounts to gain initial access to the cluster or to avoid attribution of their activities within the cluster.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_kubernetes_service_account_token_created_via_tokenrequest_aws_eks.toml
  - https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-v1/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_endpoint_permission_enumeration_by_anonymous_user_aws_eks.toml
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#unauthenticated-api-access
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_kubernetes_multi_resource_setup_recon_aws_eks.toml
  - https://attack.mitre.org/techniques/T1613/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/execution_kubernetes_pod_exec_curl_wget_https_aws_eks.toml
  - https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/kubernetes-privilege-escalation/workload-and-pod-access.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/initial_access_anonymous_request_authorized_aws_eks.toml
  - https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
rules:
  - title: Detect Suspicious TokenRequest API Creation
    description: Detects the creation of a Kubernetes service account token via the TokenRequest API by a non-system identity, which may indicate credential theft or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - webserver
      - kubernetes
  - title: Detect Authorized Anonymous Requests to EKS API
    description: Detects authorized requests from system:anonymous or system:unauthenticated users with unusual user agents, excluding standard health check endpoints.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.001
    data_sources:
      - webserver
      - kubernetes
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Cloud Security
  immediate_actions:
    - action: Enable EKS control-plane audit logging and integrate with SIEM
      owner: Cloud Security
      due: 48h
      evidence: Required for observability into the TokenRequest API
    - action: Deploy the TokenRequest API detection rule to production
      owner: Detection Engineering
      due: 72h
      evidence: High-signal detection for credential access
  hunt_leads:
    - lead: Analyze EKS audit logs for 'create' verb on 'serviceaccounts/token' by unexpected users
      technique_id: T1552.007
      data_needed:
        - aws.eks.audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies this as an indicator of abuse
updates:
  - at: "2026-10-21T08:30:11Z"
    level: L1
    summary: added coverage for Elastic Kubernetes Service (EKS)
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_endpoint_permission_enumeration_by_anonymous_user_aws_eks.toml
  - at: "2026-10-21T08:30:16Z"
    level: L1
    summary: added coverage for Elastic Kubernetes Service (EKS)
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_kubernetes_multi_resource_setup_recon_aws_eks.toml
  - at: "2026-10-21T08:30:51Z"
    level: L2
    summary: added coverage for Elastic Kubernetes Service (EKS)
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/execution_kubernetes_pod_exec_curl_wget_https_aws_eks.toml
  - at: "2026-10-21T09:06:51Z"
    level: L1
    summary: 'added detection rule: Detect Authorized Anonymous Requests to EKS API'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/initial_access_anonymous_request_authorized_aws_eks.toml
---

The Kubernetes TokenRequest API allows identities with appropriate RBAC permissions to programmatically generate short-lived tokens for service accounts. Because this process occurs via the API server, the resulting tokens do not leave traditional filesystem footprints, evading file-based monitoring. In Amazon EKS environments, attackers who have gained initial cluster access can leverage this API to mint tokens for highly privileged service accounts, effectively bypassing security controls meant to protect mounted secrets.

## Impact

Successful abuse of the TokenRequest API enables attackers to impersonate privileged service accounts, perform unauthorized cluster operations, or gain access to AWS cloud resources through IRSA (IAM Roles for Service Accounts).

## Recommendation

- Enable and ingest EKS control-plane audit logs into your SIEM as defined in the AWS integration documentation for `aws.eks_audit`.
- Deploy the detection rules provided below to monitor for `create` events against the `serviceaccounts/token` subresource by non-system identities.
- Review RBAC policies across the cluster to identify and restrict `create` permissions on the `serviceaccounts/token` subresource to only strictly necessary service accounts or users.
- Audit existing tokens minted via TokenRequest by correlating `aws.eks.audit.annotations.authentication_kubernetes_io/issued-credential-id` with subsequent API activity.
