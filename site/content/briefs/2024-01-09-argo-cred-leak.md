---
title: Argo Workflows Credentials Exposed in Pod Logs
slug: 2024-01-09-argo-cred-leak
description: Argo Workflows versions 4.0.0 to 4.0.4 log artifact repository credentials in plaintext, allowing users with read access to pod logs to extract sensitive information such as S3 access keys and GCS service account keys.
date: "2026-05-04T20:12:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - argo-workflows
  - credential-access
  - kubernetes
vendors:
  - Argoproj
  - Google
  - Microsoft
products:
  - argo-workflows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1005
    technique_name: Access Token Manipulation
cves:
  - id: CVE-2025-62157
    cvss: 6.5
    epss: 0.00035
references:
  - https://github.com/advisories/GHSA-7vf8-2cr6-54mf
rules:
  - title: Detect Kubernetes Log Access by Non-Admin Users
    description: Detects attempts to read Kubernetes pod logs by users outside of a predefined list of administrative users.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1005
    data_sources:
      - webserver
      - kubernetes
  - title: Detect Argo Workflow Log Access with Specific Pod Name
    description: Detects access to Argo Workflow logs referencing a specific pod naming pattern that may indicate credential exposure.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1005
    data_sources:
      - webserver
      - kubernetes
rules_count: 2
---

Argo Workflows, a Kubernetes-native workflow engine, is vulnerable to credential exposure. Specifically, versions 4.0.0 through 4.0.4 inadvertently log artifact repository credentials in plaintext during artifact operations. This includes sensitive data like S3 Access Keys, Secret Keys, Session Tokens, Server-Side Customer Keys, OSS Access Keys, Secret Keys, Security Tokens, and GCS Service Account Keys. The vulnerability stems from the logging driver passing the entire ArtifactDriver struct to the structured logger. Any user with read access to workflow pod logs can extract these credentials, creating a significant security risk. This is an incomplete fix of CVE-2025-62157.

## Attack Chain

1. An attacker gains read access to Kubernetes pod logs within the Argo Workflows namespace. This could be achieved through compromised credentials, misconfigured RBAC policies, or other Kubernetes vulnerabilities.
2. The attacker identifies a workflow that utilizes artifact storage, such as S3 or GCS.
3. The workflow executes an artifact operation (upload or download).
4. Argo Workflows logs the entire ArtifactDriver struct, including the plaintext credentials, into the pod logs.
5. The attacker queries the pod logs using `kubectl` or other Kubernetes tooling. For example: `kubectl -n argo logs "cred-leak-test" -c wait`.
6. The attacker extracts the plaintext credentials (e.g., S3 Access Key and Secret Key) from the log output.
7. The attacker uses the extracted credentials to access the artifact repository (e.g., S3 bucket) and potentially steal data or perform other unauthorized actions.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to artifact repositories used by Argo Workflows. This can lead to data breaches, as sensitive data stored in S3 buckets, GCS buckets, or other storage solutions can be exposed. The impact is especially severe if the compromised credentials have broad permissions or if the artifact repository contains highly sensitive data. This affects Argo Workflows versions 4.0.0, 4.0.1, 4.0.2, 4.0.3, and 4.0.4.

## Recommendation

*   Upgrade Argo Workflows to version 4.0.5 or later to remediate the vulnerability (CVE-2026-42295).
*   Review and restrict Kubernetes RBAC permissions to limit access to pod logs, following the principle of least privilege.
*   Implement log monitoring and alerting for unusual access patterns to Kubernetes pod logs.
*   Rotate any potentially exposed artifact repository credentials (S3 access keys, GCS service account keys, etc.) if Argo Workflows versions 4.0.0-4.0.4 were in use.
