---
title: Rancher Fleet Helm Impersonation Bypass Vulnerability
slug: 2026-05-rancher-fleet-bypass
description: Fleet's Helm deployer did not fully apply ServiceAccount impersonation in two code paths, allowing a tenant with git push access to a Fleet-monitored repository to read secrets from any namespace on every downstream cluster targeted by their `GitRepo`.
date: "2026-05-07T01:26:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - fleet
  - rancher
  - helm
  - kubernetes
  - impersonation
  - privilege-escalation
  - cve-2026-41050
vendors:
  - Rancher
  - SUSE
products:
  - Fleet
  - Rancher v2.14.1
  - Rancher v2.13.5
  - Rancher v2.12.9
  - Rancher v2.11.13
  - Rancher v2.10.11
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1531
    technique_name: Account Access Removal
references:
  - https://github.com/advisories/GHSA-765j-qfrp-hm3j
rules:
  - title: Detect Fleet ValuesFrom Cross Namespace Access
    description: Detects suspicious access to Secrets or ConfigMaps from different namespaces using the 'valuesFrom' feature in Fleet's helm deployments, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1531
    data_sources:
      - process_creation
      - linux
  - title: Detect Fleet Helm Lookup Cross Namespace Access
    description: Detects suspicious Helm chart deployments using 'lookup' calls to access resources in namespaces outside the intended scope, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1531
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability has been identified in Rancher's Fleet, where the Helm deployer failed to fully apply ServiceAccount impersonation in multi-tenant environments. This flaw allows users with git push access to a Fleet-monitored repository to bypass intended RBAC restrictions and read secrets from any namespace on downstream Kubernetes clusters targeted by their `GitRepo`. The vulnerability manifests in two code paths: a Helm `lookup` bypass, where Kubernetes API queries are executed with the fleet-agent's cluster-admin credentials instead of the intended impersonated ServiceAccount, and a `valuesFrom` bypass, where Secret and ConfigMap references in `fleet.yaml` are read using the cluster-admin client. This issue affects Rancher versions prior to v2.14.1, v2.13.5, v2.12.9, and v2.11.13, posing a significant risk to multi-tenant deployments.

## Attack Chain

1. An attacker gains git push access to a Fleet-monitored repository.
2. The attacker modifies a Helm chart template within the repository to include a `lookup` call that targets sensitive resources in another namespace (e.g., `lookup("v1", "Secret", "kube-system", "my-secret")`).
3. The attacker commits and pushes the malicious changes to the Git repository.
4. Fleet automatically synchronizes the changes from the Git repository.
5. The Helm template engine executes the `lookup` call using the fleet-agent's cluster-admin credentials, bypassing the impersonated ServiceAccount.
6. The attacker retrieves the contents of the targeted secret from the other namespace.
7. Alternatively, the attacker modifies the `fleet.yaml` file to include a `valuesFrom` reference to a Secret or ConfigMap in another namespace.
8. The fleet-agent retrieves the specified Secret or ConfigMap using cluster-admin credentials, again bypassing the intended RBAC restrictions.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to sensitive information, potentially including credentials, API keys, and other confidential data stored in Kubernetes secrets. The impact is especially severe in multi-tenant environments, where tenants can compromise the security of other tenants' resources. The specific impact depends on the permissions associated with the leaked credentials, and the attacker might use them to further compromise the cluster or external services. Given the critical nature of the vulnerability, prompt patching or mitigation is essential.

## Recommendation

*   Upgrade Rancher to patched versions, including `v2.14.1`, `v2.13.5`, `v2.12.9`, and `v2.11.13`, to remediate the vulnerabilities. For Rancher `v2.10.11`, manually update the Fleet deployment to version `v0.11.13`.
*   Deploy the Sigma rule `Detect Fleet ValuesFrom Cross Namespace Access` to identify attempts to access Secrets or ConfigMaps in unauthorized namespaces.
*   Deploy the Sigma rule `Detect Fleet Helm Lookup Cross Namespace Access` to detect malicious Helm chart templates attempting to bypass RBAC restrictions.
*   Restrict git push access to Fleet-monitored repositories to trusted users as much as possible to reduce the attack surface.
