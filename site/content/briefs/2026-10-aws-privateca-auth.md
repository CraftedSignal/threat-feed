---
brief_id: brief-2026-10-29-aws-privateca-auth
event_id: brief-2026-10-29-aws-privateca-auth
revision: 1
activity_at: "2026-10-29T17:53:28Z"
title: 'Amazon AWS Private CA Connector for Kubernetes: Incorrect authorization in issuer resolution (CVE-2026-119115)'
slug: 2026-10-aws-privateca-auth
description: An incorrect authorization vulnerability in the issuer resolution logic of AWS Private CA Connector for Kubernetes (aws-privateca-issuer) before v1.10.1 allows an authenticated remote user to obtain certificates, including subordinate CA certificates, that their approval policy does not authorize.
date: "2026-10-29T17:53:28Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - AWS Private CA Connector for Kubernetes (before v1.10.1)
  - aws-privateca-issuer (before v1.10.1)
cves:
  - id: CVE-2026-119115
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119115
---

AWS Private CA Connector for Kubernetes (aws-privateca-issuer) before v1.10.1 contains an incorrect authorization vulnerability in the issuer resolution logic. This may allow an authenticated remote user to obtain certificates, including subordinate CA certificates, signed by a cluster-scoped AWS Private CA issuer that their approval policy does not authorize. 

To remediate, users should upgrade aws-privateca-issuer to v1.10.1 or the AWS Private CA Connector for Kubernetes EKS add-on to v1.10.1-eksbuild.1. Users must also update any certificate requests, Certificate resources, or Ingress annotations whose issuerRef.kind is missing, incorrect, or does not match the referenced issuer, as v1.10.1 requires issuerRef.kind to be exactly AWSPCAIssuer or AWSPCAClusterIssuer.
