---
title: Fission Function Pods Leak Service Account Token, Enabling Namespace-Wide Secret Access
slug: 2026-05-fission-sa-token-leak
description: Fission runtime pods were created with the `fission-fetcher` service account, granting namespace-wide `get` access to secrets and configmaps; the runtime pod's automounted token was reachable from inside the user's function container, allowing user-supplied function code to inherit the same Kubernetes API privileges and read any secret or configmap in the function's namespace, far beyond the intended `Function.spec.secrets` allowlist.
date: "2026-05-21T20:18:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - kubernetes
  - faas
vendors:
  - Fission
products:
  - fission/fission (<= 1.22.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-85g2-pmrx-r49q
  - https://github.com/fission/fission/releases/tag/v1.23.0
  - https://github.com/fission/fission/pull/3366
rules:
  - title: Detect Fission Function Pod Accessing Kubernetes API Token Path
    description: Detects a Fission function pod attempting to read the Kubernetes service account token file, which could indicate an attempt to exploit CVE-2026-46617.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - file_event
      - linux
  - title: Detect Fission Function Pod Connecting to Kubernetes API Server
    description: Detects a Fission function pod establishing a network connection to the Kubernetes API server, which is abnormal unless explicitly intended, and could indicate exploitation of CVE-2026-46617.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - privilege_escalation
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Fission is a function-as-a-service (FaaS) framework for Kubernetes. Prior to version 1.23.0, Fission runtime pods were configured with the `fission-fetcher` service account, which had broad permissions to read secrets and configmaps within its namespace. This was necessary for the fetcher sidecar to retrieve function code, environment variables, and configuration data. However, the service account token was automatically mounted into the user's function container at `/var/run/secrets/kubernetes.io/serviceaccount/token`. This exposed the token to user-supplied function code, granting it unintended Kubernetes API privileges and the ability to read any secret or configmap in the function's namespace, bypassing the intended security controls defined by `Function.spec.secrets`. This vulnerability allows malicious function code to escalate privileges and access sensitive data within the Kubernetes namespace.

## Attack Chain

1. An attacker gains the ability to deploy or update a Fission `Function` or `Package` resource in a Kubernetes namespace.
2. The attacker crafts a malicious function that reads the service account token file located at `/var/run/secrets/kubernetes.io/serviceaccount/token`.
3. The function uses the token to authenticate against the Kubernetes API server.
4. The function queries the Kubernetes API to list and read all secrets within the namespace.
5. The function retrieves sensitive data from the secrets, such as TLS keys, OIDC client secrets, database credentials, or cloud provider credentials.
6. The function queries the Kubernetes API to list and read all configmaps within the namespace.
7. The attacker uses the stolen credentials to pivot to other Kubernetes resources or external systems.
8. The attacker compromises other systems or resources using the obtained credentials.

## Impact

Successful exploitation of this vulnerability allows an attacker to read every secret and configmap within a Kubernetes namespace where Fission runtime pods are scheduled. This could include sensitive information such as database credentials, API keys, and TLS certificates. By gaining access to these secrets, an attacker could potentially compromise other applications and services running within the cluster, or even gain unauthorized access to external systems. The vulnerability violates the principle that `Function.spec.secrets` should be the sole declaration of secrets accessible to a function.

## Recommendation

- Upgrade to Fission version 1.23.0 or later, where the user function container has `AutomountServiceAccountToken` set to `false` at the container level to prevent the token leak, as described in [PR #3366](https://github.com/fission/fission/pull/3366).
- Until an upgrade is possible, restrict who can create or update `Function` and `Package` CRDs in your cluster, treating function code deployment as equivalent to namespace-wide secret read.
- Reduce the scope of the `fission-fetcher` ClusterRole/Role where possible, limiting access to specific named secrets via separate Role bindings.
- Implement NetworkPolicy egress rules to deny function pods access to the Kubernetes API server, mitigating the impact of a token leak.
