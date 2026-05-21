---
title: Amazon SageMaker Python SDK HMAC Key Leakage via API Exposure
slug: 2026-05-sagemaker-hmac-leak
description: Amazon SageMaker Python SDK exposes an HMAC signing key in cleartext via API calls, enabling a remote authenticated actor to forge model artifacts and achieve code execution.
date: "2026-05-21T17:44:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sagemaker
  - hmac
  - key-leakage
  - cloud
  - privilege-escalation
vendors:
  - Amazon
products:
  - SageMaker Python SDK
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-7hh5-prp2-mfh5
  - https://aws.amazon.com/security/vulnerability-reporting
rules:
  - title: Detect SageMaker API Calls Revealing HMAC Key - DescribeModel
    description: Detects calls to the SageMaker DescribeModel API that may reveal the SAGEMAKER_SERVE_SECRET_KEY in plaintext within the container environment configuration.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - cloudtrail
  - title: Detect SageMaker API Calls Revealing HMAC Key - DescribeEndpointConfig
    description: Detects calls to the SageMaker DescribeEndpointConfig API that may reveal the SAGEMAKER_SERVE_SECRET_KEY in plaintext within the container environment configuration.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - cloudtrail
  - title: Detect SageMaker API Calls Revealing HMAC Key - DescribeModelPackage
    description: Detects calls to the SageMaker DescribeModelPackage API that may reveal the SAGEMAKER_SERVE_SECRET_KEY in plaintext within the container environment configuration.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - cloudtrail
rules_count: 3
---

The Amazon SageMaker Python SDK, a library for training and deploying machine learning models on Amazon SageMaker, contains a vulnerability related to the ModelBuilder/Serve component. Specifically, when building and deploying models with affected model servers (TorchServe, Multi-Model Server, TensorFlow Serving, SMD, or Triton), the SDK inadvertently stores an HMAC secret key in cleartext as the `SAGEMAKER_SERVE_SECRET_KEY` environment variable within the SageMaker model container configuration. This sensitive environment variable is then exposed in plaintext through the `DescribeModel`, `DescribeEndpointConfig`, and `DescribeModelPackage` APIs. This vulnerability affects versions >= v2.199.0 AND <= v2.257.1, as well as versions >= v3.0.0 AND <= v3.7.1. Defenders must upgrade to the patched versions and rebuild models to remediate the risk.

## Attack Chain

1. Attacker gains authenticated access to the AWS environment.
2. Attacker enumerates SageMaker models via `DescribeModel`, `DescribeEndpointConfig`, or `DescribeModelPackage` API calls.
3. The API response reveals the `SAGEMAKER_SERVE_SECRET_KEY` in plaintext within the container environment configuration.
4. Attacker gains S3 write access to the model artifact path.
5. Attacker crafts a malicious model artifact, forging a valid integrity signature using the leaked HMAC key.
6. Attacker uploads the forged model artifact to the S3 bucket, replacing the original model.
7. The compromised model is deployed to an inference container.
8. Upon execution, the malicious model executes code within the SageMaker execution role's IAM permissions, leading to potential privilege escalation.

## Impact

Successful exploitation of this vulnerability allows an attacker with authenticated access and S3 write permissions to achieve code execution within SageMaker inference containers. The attacker can leverage the SageMaker execution role's IAM permissions, potentially leading to privilege escalation, data exfiltration, or other malicious activities. The number of affected SageMaker models is dependent on the number of organizations using ModelBuilder with vulnerable SDK versions to create and deploy models. If this attack succeeds, it allows attackers to take complete control over SageMaker machine learning models.

## Recommendation

*   Upgrade the Amazon SageMaker Python SDK to versions v2.257.2 or v3.8.0 or later to address the vulnerability as stated in the advisory.
*   Rebuild any models previously created with ModelBuilder using the updated SDK to ensure the sensitive HMAC key is not stored in the container environment variables.
*   Monitor AWS CloudTrail logs for API calls to `DescribeModel`, `DescribeEndpointConfig`, and `DescribeModelPackage` to detect potential enumeration attempts by attackers.
*   Implement strict IAM policies to limit access to the `DescribeModel`, `DescribeEndpointConfig`, and `DescribeModelPackage` APIs and S3 write access to model artifact paths.
