---
title: Fleet PSS Bypass Vulnerability (CVE-2026-44938) via addLabelsFromOptions
slug: 2026-07-fleet-pss-bypass
description: A vulnerability in Fleet's agent-side deployer (CVE-2026-44938) allows an attacker with `git push` access to a Fleet-monitored repository to overwrite Pod Security Standards (PSS) enforcement labels on target Kubernetes namespaces, bypassing admission controls and enabling the deployment of otherwise prohibited workloads.
date: "2026-07-03T12:27:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - fleet
  - pss-bypass
  - admission-controller
  - supply-chain
  - defense-evasion
vendors:
  - Rancher
  - SUSE
products:
  - Fleet >= 0.15.0, < 0.15.2
  - Fleet >= 0.14.0, < 0.14.6
  - Fleet >= 0.13.0, < 0.13.11
  - Fleet >= 0.12.0, < 0.12.15
references:
  - https://github.com/advisories/GHSA-864g-863m-vcvq
  - https://attack.mitre.org/techniques/T1685/
  - CVE-2026-44938
---

A high-severity vulnerability, CVE-2026-44938, has been discovered in the Fleet agent's deployer component. This flaw allows an attacker who has gained `git push` access to a Fleet-monitored repository to manipulate Pod Security Standards (PSS) enforcement labels. Specifically, the `addLabelsFromOptions` function within the agent fails to properly filter security-sensitive `pod-security.kubernetes.io/` prefixed labels from `namespaceLabels` defined in `fleet.yaml` or `BundleDeployment.spec.options.namespaceLabels`. This oversight permits an attacker to overwrite and effectively downgrade PSS policies on a target Kubernetes namespace, thereby weakening admission controls and enabling the deployment of malicious or privileged workloads that would normally be blocked. The vulnerability impacts various versions of Fleet, including `0.15.0` to `0.15.1`, `0.14.0` to `0.14.5`, `0.13.0` to `0.13.10`, and `0.12.0` to `0.12.14`. This presents a significant risk to Kubernetes cluster integrity, as it can be leveraged to bypass critical security mechanisms.

## Attack Chain

1.  **Initial Access (Git Repository)**: Attacker gains `git push` access to a Fleet-monitored Git repository, potentially via compromised developer credentials or an insider threat.
2.  **Configuration Modification**: Attacker modifies the `fleet.yaml` file (or `BundleDeployment.spec.options.namespaceLabels`) within the compromised repository to include or modify `namespaceLabels` that override or downgrade existing Pod Security Standards.
3.  **Code Commit and Push**: The malicious configuration change is committed and pushed to the Fleet-monitored Git repository.
4.  **Fleet Agent Deployment**: The Fleet agent, observing changes in the Git repository, pulls the updated `fleet.yaml` and attempts to apply the `namespaceLabels` to the target Kubernetes namespace.
5.  **PSS Label Overwrite**: Due to CVE-2026-44938, the Fleet agent fails to filter security-sensitive `pod-security.kubernetes.io/` labels, inadvertently overwriting legitimate PSS enforcement labels on the target namespace.
6.  **Admission Control Weakening**: The target Kubernetes namespace's Pod Security Standard admission controls are effectively downgraded or disabled, allowing higher-privileged workloads to be deployed.
7.  **Malicious Workload Deployment**: The attacker then deploys a malicious or privileged Kubernetes workload (e.g., a container running as root, with hostPath mounts, or network access) to the now-weakened namespace.
8.  **Impact**: The deployed malicious workload executes, leading to potential confidentiality breaches (data exfiltration), integrity compromises (system modification), or availability issues (resource consumption, denial of service) within the Kubernetes cluster.

## Impact

Successful exploitation of CVE-2026-44938 allows an attacker to bypass Kubernetes Pod Security Standards (PSS) enforcement on affected namespaces, leading to weakened admission controls. This enables the deployment of privileged or otherwise restricted workloads, which can then be leveraged for unauthorized data exfiltration, system compromise, or disruption of services within the Kubernetes cluster. The ultimate impact on confidentiality, integrity, and availability depends on the specific permissions and actions of the attacker-deployed workload. While no specific victim counts are provided, any organization utilizing vulnerable Fleet versions in a multi-tenant or multi-developer environment where `git push` access could be compromised is at risk.

## Recommendation

*   **Patch Immediately**: Upgrade your Fleet deployments to a patched version (v0.15.2, v0.14.6, v0.13.11, or v0.12.15) to mitigate CVE-2026-44938.
*   **Implement NeuVector Workaround**: If immediate patching is not possible, deploy NeuVector (SUSE Security) and configure an admission control Deny rule for "Run as privileged" in Protect mode. NeuVector evaluates pod specs independently of Kubernetes PSS namespace labels, blocking privileged containers even if PSS labels are downgraded due to CVE-2026-44938.
*   **Restrict Repository Access**: Implement strict access controls for Git repositories monitored by Fleet, particularly in multi-tenant environments, to reduce the attack surface for CVE-2026-44938.
*   **Review Credentials**: Review your systems for potentially leaked credentials and replace any that may be compromised, as `git push` access is a prerequisite for exploiting CVE-2026-44938.
