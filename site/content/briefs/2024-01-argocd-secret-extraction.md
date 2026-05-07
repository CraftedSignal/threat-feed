---
title: ArgoCD ServerSideDiff Secret Extraction Vulnerability
slug: 2024-01-argocd-secret-extraction
description: A missing authorization and data-masking gap in Argo CD's ServerSideDiff endpoint allows an attacker with read-only access to extract plaintext Kubernetes Secret data from etcd via the Kubernetes API server's Server-Side Apply dry-run mechanism, affecting versions v3.2.0-v3.2.10 and v3.3.0-v3.3.8.
date: "2026-05-07T01:56:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - argocd
  - secret-extraction
  - kubernetes
  - credential-access
vendors:
  - GitHub
products:
  - argo-cd
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-3v3m-wc6v-x4x3
rules:
  - title: Detect ArgoCD ServerSideDiff Secret Extraction Attempt
    description: Detects potential attempts to exploit the ArgoCD ServerSideDiff vulnerability by monitoring requests to the vulnerable endpoint.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect ArgoCD Application with IncludeMutationWebhook Annotation
    description: Detects creation or modification of ArgoCD applications with the IncludeMutationWebhook annotation enabled, which increases the attack surface for the ServerSideDiff vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in Argo CD's ServerSideDiff endpoint that allows for the extraction of plaintext Kubernetes Secret data. The vulnerability stems from a missing authorization and data-masking gap in the `/application.ApplicationService/ServerSideDiff` endpoint. This allows an attacker with read-only access to extract plaintext Kubernetes Secret data from etcd via the Kubernetes API server's Server-Side Apply dry-run mechanism. The issue affects Argo CD versions v3.2.0 through v3.2.10 and v3.3.0 through v3.3.8. Exploitation is possible by any user with Argo CD application get permissions, potentially exposing sensitive information such as service account tokens, TLS certificates, database credentials, and API keys. The impact is heightened when the `IncludeMutationWebhook=true` annotation is set on Applications, as this bypasses a defense layer and makes exploitation easier.

## Attack Chain

1.  Attacker authenticates to Argo CD with read-only access or leverages existing access.
2.  Attacker identifies an Argo CD Application with the `argocd.argoproj.io/compare-options: IncludeMutationWebhook=true` annotation.
3.  Attacker identifies Kubernetes Secrets managed by Argo CD within the targeted Application.
4.  Attacker crafts a malicious request to the `/application.ApplicationService/ServerSideDiff` endpoint, targeting the identified Secret.  The request simulates a server-side dry-run apply operation.
5.  The `ServerSideDiff` function, due to the `IncludeMutationWebhook=true` setting, skips the `removeWebhookMutation()` defense, which would normally mask sensitive data.
6.  The Kubernetes API server processes the dry-run request, retrieving the unmasked Secret data from etcd.
7.  The raw, unmasked Secret data is included in the API response to the attacker.
8.  Attacker parses the response, extracts the plaintext Secret data, and uses it for unauthorized access or lateral movement.

## Impact

Successful exploitation of this vulnerability allows any user with Argo CD application get permissions to extract real Kubernetes Secret values. This can lead to the exposure of sensitive data, including service account tokens, TLS certificates, database credentials, and API keys. Depending on the permissions associated with the compromised secrets, attackers can gain unauthorized access to other systems, escalate privileges, or perform lateral movement within the Kubernetes cluster. The vulnerability affects Argo CD versions between 3.2.0 and 3.2.11 and between 3.3.0 and 3.3.9.

## Recommendation

*   Upgrade Argo CD to version v3.2.11 or v3.3.9 or later to patch CVE-2026-42880.
*   Review Argo CD Applications for the presence of the `argocd.argoproj.io/compare-options: IncludeMutationWebhook=true` annotation and remove it where not strictly necessary.
*   Deploy the Sigma rule `Detect ArgoCD ServerSideDiff Secret Extraction Attempt` to detect suspicious requests to the `/application.ApplicationService/ServerSideDiff` endpoint.
*   Monitor Argo CD logs for unusual activity related to the `ServerSideDiff` function.
