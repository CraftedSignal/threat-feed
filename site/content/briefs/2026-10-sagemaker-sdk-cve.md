---
brief_id: brief-2026-10-21-sagemaker-sdk-cve
event_id: brief-2026-10-21-sagemaker-sdk-cve
revision: 1
activity_at: "2026-10-21T23:49:55Z"
title: 'Amazon SageMaker Python SDK: S3 bucket pre-creation remote code execution (CVE-2026-112408)'
slug: 2026-10-sagemaker-sdk-cve
description: The Amazon SageMaker Python SDK fails to verify S3 bucket ownership in the default_bucket() function, allowing attackers to pre-create predictable buckets for IAM credential theft or remote code execution.
date: "2026-10-21T23:49:55Z"
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
  validation_status: Source verified; no environment validation required.
cpes:
  - cpe:2.3:a:amazon:sagemaker_python_sdk:*:*:*:*:*:*:*:*
tags:
  - cloud-security
  - remote-code-execution
  - credential-theft
  - amazon
vendors:
  - Amazon
products:
  - SageMaker Python SDK (< 3.10.0, < 2.257.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A remote attacker can exploit this by pre-creating an S3 bucket with a predictable name, allowing them to intercept sensitive IAM credentials or achieve remote code execution within the SageMaker execution environment.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: A remote attacker can exploit this by pre-creating an S3 bucket with a predictable name, allowing them to intercept sensitive IAM credentials.
    confidence_band: high
cves:
  - id: CVE-2026-112408
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112408
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Cloud Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade Amazon SageMaker Python SDK to version 3.10.0 or 2.257.3
      owner: IT Operations
      addresses: CVE-2026-112408
      evidence: To remediate this issue, users should upgrade to Amazon SageMaker Python SDK 3.10.0 (V3) or 2.257.3 (V2).
---

CVE-2026-112408 identifies a vulnerability in the Amazon SageMaker Python SDK where the default_bucket() function does not perform adequate ownership validation of S3 buckets. An attacker who can predict the name of an S3 bucket that the SDK intends to use can pre-create that bucket. Because the SDK fails to verify its own ownership or the existence of a prior owner, it may proceed to use the attacker-controlled bucket. This can lead to the exposure of IAM credentials used by the SageMaker execution environment or allow for remote code execution within that environment.

## Impact

Successful exploitation may result in the compromise of IAM credentials associated with the SageMaker execution role and remote code execution within the SageMaker environment.

## Recommendation

Upgrade the Amazon SageMaker Python SDK to version 3.10.0 (for V3 users) or 2.257.3 (for V2 users) to implement proper bucket ownership validation.
