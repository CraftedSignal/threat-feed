---
brief_id: brief-2026-10-21-eks-self-subject-review
event_id: brief-2026-10-21-eks-self-subject-review
revision: 1
activity_at: "2026-10-21T08:30:23Z"
title: 'AWS EKS: Suspicious Self-Subject Review via Unusual User Agent'
slug: 2026-10-eks-self-subject-review
description: |
  This rule detects when a service account or node enumerates its own permissions via the selfsubjectaccessreview or selfsubjectrulesreview APIs using an unusual user agent, which may indicate compromised credentials.
date: "2026-10-21T08:30:23Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - AWS
  - Kubernetes
  - Discovery
  - Threat Detection
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    subtechnique_id: T1069.003
    subtechnique_name: Cloud Groups
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_suspicious_self_subject_review_aws_eks.toml
  - https://attack.mitre.org/techniques/T1069/
  - https://attack.mitre.org/techniques/T1613/
---

Adversaries who have gained access to service account or node credentials may attempt to determine 
their privileges to facilitate further movement or execution within the cluster. Kubernetes APIs 
such as selfsubjectaccessreview and selfsubjectrulesreview are intended for permission debugging 
but can be exploited for privilege enumeration. This detection identifies these API calls when 
performed by service accounts or nodes using non-standard user agents.

## False Positives
- Automated tasks or service accounts programmed to perform routine permission checks.
- Nodes performing legitimate self-assessment for compliance or security.
- Development or testing environments with frequent permission verification.

## Investigation
- Identify the service account or node using `aws.eks.audit.user.username` or `aws.eks.audit.impersonatedUser.username`.
- Analyze the `aws.eks.audit.objectRef.resource` to confirm the API call type.
- Evaluate the IP address and user agent in the audit logs against expected traffic patterns.
- Review recent changes to permissions or roles associated with the implicated identity.
