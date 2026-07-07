---
title: AWS Lambda Layer Shared Externally
slug: 2026-07-aws-lambda-layer-shared-externally
description: This brief identifies the critical risk of an AWS Lambda layer's permission policy being modified, typically via the `AddLayerVersionPermission` API, to grant external AWS accounts, AWS Organizations, or the public access, potentially leading to the leakage of proprietary code or secrets and creating a supply-chain vector for attacker-influenced code execution in downstream functions.
date: "2026-07-03T16:16:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - lambda
  - supply-chain
  - misconfiguration
  - data-leakage
vendors:
  - AWS
products:
  - AWS Lambda
  - Lambda layers
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Serverless Execution
    evidence: Lambda layers package code and dependencies that are loaded into the execution environment of any function that references them.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: Identifies the modification of an AWS Lambda layer permission policy to grant another AWS account, an AWS Organization, or the public the ability to use a layer version.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/lambda/latest/dg/chapter-layers.html
  - https://docs.aws.amazon.com/lambda/latest/api/API_AddLayerVersionPermission.html
rules:
  - title: AWS Lambda Layer Shared Externally
    description: Detects the modification of an AWS Lambda layer permission policy to grant external AWS accounts, AWS Organizations, or the public the ability to use a layer version, indicating potential data leakage or supply-chain risk.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1578
      - T1578.005
      - T1648
    data_sources:
      - cloud
      - aws.cloudtrail
rules_count: 1
---

This threat focuses on the malicious or accidental configuration change of an AWS Lambda layer's permission policy, detected when an entity modifies permissions to grant access to external AWS accounts, entire AWS Organizations, or even the public. The primary mechanism for this action is the `AddLayerVersionPermission` API call. This configuration allows other entities to utilize the code and dependencies packaged within the Lambda layer. Such external sharing, especially with the public, presents a significant risk of exposing proprietary code, sensitive data, or embedded secrets. Furthermore, it creates a potential supply-chain attack vector, where compromised or malicious layers could inject attacker-influenced code into functions that reference them, impacting their runtime integrity and leading to further compromise. While legitimate cross-account sharing can occur, public or broad external sharing warrants immediate and thorough investigation due to its severe security implications.

## Attack Chain

[Omitted - The source describes a specific configuration change and its potential implications, not a multi-stage attack chain.]

## Impact

Successful external sharing of an AWS Lambda layer can result in the direct exposure and leakage of an organization's proprietary code and sensitive data, including API keys, database credentials, or other secrets embedded within the layer. If exploited as a supply-chain vector, an attacker could introduce malicious code into functions referencing the compromised layer, leading to various impacts such as unauthorized data exfiltration, remote code execution (RCE) within the function's execution environment, denial of service, or further lateral movement within the cloud environment. The broadness of access granted (e.g., to the public or an entire organization) directly correlates with the potential number of impacted entities and the scope of information exposure.

## Recommendation

*   Deploy the provided Sigma rule to detect `AddLayerVersionPermission` calls in your AWS CloudTrail logs, particularly those granting public or external account access.
*   Investigate all instances of `AddLayerVersionPermission` where the `principal` in `aws.cloudtrail.request_parameters` is `*` (public) or an external AWS account ID.
*   Validate the `layerName` and the granted `principal` against approved sharing practices for your organization, as noted in the `false_positives` section.
*   If unauthorized sharing is detected, immediately remove the layer permission using the `RemoveLayerVersionPermission` API call and rotate any secrets that may have been exposed within the layer.
*   Restrict the `lambda:AddLayerVersionPermission` IAM permission to a limited set of trusted roles and principals to reduce the attack surface.
