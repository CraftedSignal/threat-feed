---
title: AWS Lateral Movement via Kubernetes Service Account Identity Exploitation
slug: 2026-09-aws-k8s-lateral-movement
description: Adversaries are exploiting Kubernetes service account tokens exchanged for AWS IAM credentials via AssumeRoleWithWebIdentity to conduct unauthorized reconnaissance, credential theft, and persistent access within AWS environments.
date: "2026-09-18T19:37:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - lateral-movement
  - credential-access
  - discovery
vendors:
  - Amazon
products:
  - AWS Elastic Kubernetes Service (EKS)
  - AWS IAM
  - AWS STS
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.007
    technique_name: Cloud Services
    evidence: Adversaries leverage the short-lived IAM credentials generated for pods to perform unauthorized reconnaissance, access sensitive secrets, modify IAM configurations, or manipulate compute resources.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
    evidence: Adversaries leverage the short-lived IAM credentials generated for pods to perform unauthorized reconnaissance.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555.006
    technique_name: Cloud Secrets Management Stores
    evidence: Access sensitive secrets, modify IAM configurations.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550.001
    technique_name: Application Access Token
    evidence: Detects when credentials issued through AssumeRoleWithWebIdentity for a Kubernetes service account identity are later used for several distinct AWS control-plane actions.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
  - https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/lateral_movement_k8_assumed_web_identity_session_with_multi_phase_api_use.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy ES-QL rule for AWS lateral movement detection in production environment.
      owner: Detection Engineering
      due: 48h
      evidence: Source provided production-ready ES-QL rule.
  hunt_leads:
    - lead: Identify IAM roles assumed by Kubernetes service accounts that are performing administrative actions (e.g., ModifyInstanceAttribute, CreateAccessKey) outside of expected patterns.
      technique_id: T1550.001
      data_needed:
        - AWS CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies these actions as post-exploit indicators.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict IAM policies for all EKS-associated service accounts to follow least privilege.
      owner: IT Operations
      addresses: T1555.006
      evidence: Source recommends tightening OIDC trust conditions and reducing permissions.
---

This threat involves the exploitation of Kubernetes service account (SA) identities within Amazon EKS environments. Attackers leverage the EKS IAM Roles for Service Accounts (IRSA) feature, where a projected Kubernetes token is exchanged for short-lived AWS IAM credentials via the 'AssumeRoleWithWebIdentity' API. Once an adversary gains control of a pod or a compromised service account token, they use the resulting IAM session to move laterally from the containerized environment to the AWS control plane.

Observed activity includes automated reconnaissance, unauthorized access to secret management stores (AWS Secrets Manager/Parameter Store), and modifications to IAM configurations or compute instances. Defenders should focus on identifying sessions where the initial web identity token exchange is immediately followed by a high volume of non-routine administrative API calls, distinguishing this from standard pod traffic. The scope of this threat encompasses any AWS workload utilizing IRSA that is susceptible to unauthorized token use off-cluster or within the pod.

## Attack Chain

1. Initial access: Adversary gains execution capability within a Kubernetes pod, often via exploit of a web application or misconfigured service.
2. Credential acquisition: Adversary locates the projected Kubernetes service account token, typically mounted at `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`.
3. Token exchange: Adversary uses the service account token to call the 'AssumeRoleWithWebIdentity' API, obtaining short-lived AWS IAM session credentials.
4. Reconnaissance: Adversary uses the obtained IAM session to call discovery APIs such as 'ListRoles', 'ListUsers', or 'ListBuckets' to map the AWS environment.
5. Credential access: Adversary accesses sensitive configuration data, including 'GetSecretValue' from AWS Secrets Manager or 'GetParameters' from Parameter Store.
6. Persistence: Adversary utilizes the session to perform IAM modifications, such as 'CreateAccessKey' or 'AttachRolePolicy', to ensure continued access.
7. Impact: Adversary achieves final objectives, such as data exfiltration from S3 buckets, code manipulation in Lambda, or full environment compromise.

## Impact

Successful exploitation allows attackers to bypass Kubernetes-level security controls and gain significant privileges within the AWS account. This can result in the compromise of sensitive credentials, unauthorized modification of infrastructure, and potential exfiltration of proprietary data or intellectual property. The threat specifically impacts organizations running EKS with IRSA where service accounts are over-privileged or lack sufficient monitoring of control-plane activity.

## Recommendation

1. Implement the detection logic described in the provided ES-QL rule to correlate 'AssumeRoleWithWebIdentity' events with subsequent high-impact administrative API calls.
2. Review AWS CloudTrail logs for unexpected usage of IRSA-issued session keys originating from IP addresses or ASNs outside of the EKS cluster's VPC or NAT gateways.
3. Enforce the principle of least privilege for IAM roles associated with service accounts; audit and restrict the policies attached to these roles to the absolute minimum required permissions.
4. Strengthen OIDC trust conditions by utilizing 'sub' and 'aud' claims to restrict role assumption to specific, verified Kubernetes namespaces and service accounts.
5. Conduct periodic audits of EKS audit logs to detect anomalous 'exec' activity or unauthorized secret access attempts within the cluster.
