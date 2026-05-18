---
title: Kubernetes Rapid Secret GET Activity Against Multiple Objects
slug: 2026-05-kubernetes-secret-retrieval-burst
description: This rule detects an unusual volume of Kubernetes API get requests against multiple distinct Secret objects from the same client fingerprint, potentially indicating credential access or in-cluster reconnaissance.
date: "2026-05-18T09:45:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - credential-access
  - cloud
products:
  - kubernetes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/credential_access_kubernetes_multiple_secret_retrieval_burst.toml
  - https://attack.mitre.org/techniques/T1552/007/
rules:
  - title: Kubernetes Rapid Secret GET Activity Against Multiple Objects
    description: Detects rapid retrieval of multiple Kubernetes secrets from the same source IP and user, indicating potential credential access or reconnaissance.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - auditd
      - kubernetes
  - title: Kubernetes Secret Get Request to Sh.Helm.Release Secret Name
    description: Detects Kubernetes secret GET requests targeting secrets with names matching sh.helm.release.*, which may indicate enumeration of helm release secrets.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1069
    data_sources:
      - auditd
      - kubernetes
rules_count: 2
---

This detection rule identifies suspicious activity within Kubernetes environments where a single client fingerprint (defined by user, source IP, and user agent) rapidly requests multiple distinct Secret objects via the Kubernetes API. This behavior can signify an attacker attempting to access sensitive information such as service account tokens, registry credentials, TLS material, or application configurations. The rule includes both successful and failed `get` requests to detect reconnaissance efforts, even when access is denied due to RBAC restrictions. The rule uses a six-minute lookback window to identify bursts of activity. The original detection logic was created on 2026-04-22 and updated on 2026-05-15.

## Attack Chain

1. An attacker gains initial access to a Kubernetes cluster, possibly through compromised credentials or a vulnerable application.
2. The attacker uses their access to query the Kubernetes API for available Secret objects.
3. The attacker sends a series of `get` requests to the Kubernetes API, targeting multiple distinct Secret objects.
4. The API server processes each request, checking the user's RBAC permissions.
5. The attacker may receive successful responses for Secrets they have permission to access.
6. The attacker may receive "forbidden" or "unauthorized" responses for Secrets they lack permission to access, potentially revealing RBAC boundaries or confirming the existence of targeted secrets.
7. The attacker analyzes the retrieved Secret data, searching for valuable credentials or configuration information.
8. The attacker uses the acquired credentials to further compromise the cluster or access external resources.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data stored in Kubernetes Secrets, including service account tokens, registry credentials, and application configurations. This can result in privilege escalation, data breaches, and lateral movement within the cluster and connected infrastructure. The rule aims to detect reconnaissance and credential access attempts, preventing attackers from successfully compromising sensitive data.

## Recommendation

*   Deploy the Sigma rule "Kubernetes Rapid Secret GET Activity Against Multiple Objects" to your SIEM and tune the threshold (Esql.unique_credentials) based on your environment to reduce false positives.
*   Investigate alerts triggered by this rule by inspecting the `Esql.outcome` field for a mix of allow vs deny responses and whether failures cluster on sensitive namespaces.
*   Enable Kubernetes audit logging to ensure the necessary data is available for detection.
*   Review RBAC configurations to ensure least privilege and restrict access to sensitive Secrets.
*   Consider implementing network policies to restrict pod-to-pod communication and limit the attack surface.
