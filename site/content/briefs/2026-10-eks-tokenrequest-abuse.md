---
brief_id: brief-2026-10-21-eks-tokenrequest-abuse
event_id: brief-2026-10-21-eks-tokenrequest-abuse
revision: 1
activity_at: "2026-10-21T07:47:08Z"
title: 'Amazon EKS: Improper TokenRequest API usage detection'
slug: 2026-10-eks-tokenrequest-abuse
description: Attackers can abuse the Kubernetes TokenRequest API to mint service account tokens without filesystem access, facilitating privilege escalation and movement to cloud resources via IAM Roles for Service Accounts (IRSA).
date: "2026-10-21T07:47:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/credential_access_kubernetes_service_account_token_created_via_tokenrequest_aws_eks.toml
  - https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-v1/
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
rules_count: 1
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
---

The Kubernetes TokenRequest API allows identities with appropriate RBAC permissions to programmatically generate short-lived tokens for service accounts. Because this process occurs via the API server, the resulting tokens do not leave traditional filesystem footprints, evading file-based monitoring. In Amazon EKS environments, attackers who have gained initial cluster access can leverage this API to mint tokens for highly privileged service accounts, effectively bypassing security controls meant to protect mounted secrets.

## Impact

Successful abuse of the TokenRequest API enables attackers to impersonate privileged service accounts, perform unauthorized cluster operations, or gain access to AWS cloud resources through IRSA (IAM Roles for Service Accounts).

## Recommendation

- Enable and ingest EKS control-plane audit logs into your SIEM as defined in the AWS integration documentation for `aws.eks_audit`.
- Deploy the detection rules provided below to monitor for `create` events against the `serviceaccounts/token` subresource by non-system identities.
- Review RBAC policies across the cluster to identify and restrict `create` permissions on the `serviceaccounts/token` subresource to only strictly necessary service accounts or users.
- Audit existing tokens minted via TokenRequest by correlating `aws.eks.audit.annotations.authentication_kubernetes_io/issued-credential-id` with subsequent API activity.
