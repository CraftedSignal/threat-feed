---
brief_id: brief-2026-10-20-aws-cicd-priv-esc
event_id: brief-2026-10-20-aws-cicd-priv-esc
revision: 1
activity_at: "2026-10-20T21:56:43Z"
title: 'Amazon: Incorrect privilege assignment in CICD-toolchain-for-serverless-applications (CVE-2026-112407)'
slug: 2026-10-aws-cicd-priv-esc
description: An incorrect privilege assignment in the IAM policy of AWS CICD-toolchain-for-serverless-applications (versions 1.0.7-1.0.10) allows authenticated users with repository push access to perform unauthorized privilege escalation and resource modification across an AWS account.
date: "2026-10-20T21:56:43Z"
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
cpes:
  - cpe:2.3:a:amazon:cicd-toolchain-for-serverless-applications:1.0.7:*:*:*:*:*:*:*
  - cpe:2.3:a:amazon:cicd-toolchain-for-serverless-applications:1.0.8:*:*:*:*:*:*:*
  - cpe:2.3:a:amazon:cicd-toolchain-for-serverless-applications:1.0.9:*:*:*:*:*:*:*
  - cpe:2.3:a:amazon:cicd-toolchain-for-serverless-applications:1.0.10:*:*:*:*:*:*:*
vendors:
  - Amazon
products:
  - CICD-toolchain-for-serverless-applications (1.0.7-1.0.10)
cves:
  - id: CVE-2026-112407
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112407
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade CICD-toolchain-for-serverless-applications to 1.0.11 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-112407 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected toolchain stacks to version 1.0.11
      owner: IT Operations
      addresses: CVE-2026-112407
      evidence: NVD advisory
---

The AWS CICD-toolchain-for-serverless-applications, specifically versions 1.0.7 through 1.0.10, is impacted by an incorrect privilege assignment vulnerability (CVE-2026-112407). This vulnerability resides within the IAM policies defined by the toolchain. Remote authenticated users who possess push access to the application source repository can exploit the CI/CD pipeline deployment process. By crafting malicious application templates, an attacker can cause the pipeline to deploy resources or execute operations that exceed the intended scope of the application stack, effectively escalating privileges to interact with or modify other resources within the same AWS account. This flaw poses a significant risk to environment isolation and least-privilege configurations. Defenders should prioritize updating to version 1.0.11 or later to secure the toolchain's IAM policy.
