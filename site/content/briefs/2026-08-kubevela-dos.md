---
title: KubeVela Terraform Remote Loader Denial of Service via Unbounded File Read
slug: 2026-08-kubevela-dos
description: An attacker with ComponentDefinition management permissions can trigger a control-plane denial of service in KubeVela by injecting a symlink to /dev/zero within a remote Terraform repository, causing an OOM-induced controller crash.
date: "2026-08-28T21:19:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:kubevela:vela-core:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - kubernetes
  - kubevela
vendors:
  - KubeVela
products:
  - vela-core (< 1.9.14)
  - vela-core (>= 1.10.0-alpha.1, < 1.10.9)
  - vela-core (>= 1.11.0-alpha.1, < 1.11.0-alpha.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The controller follows the symlink and calls os.ReadFile before HCL parsing, so memory grows until the controller is OOM killed.
    confidence_band: med
cves:
  - id: CVE-2026-55108
    cvss: 8.5
references:
  - https://github.com/advisories/GHSA-fmgp-q6jx-gg3x
  - https://github.com/kubevela/kubevela/blob/a24d3a9c6/pkg/controller/utils/capability.go
action_plan:
  priority: elevated
  owners:
    - Infrastructure Engineering
    - Security Operations
  immediate_actions:
    - action: Upgrade vela-core to version 1.9.14, 1.10.9, or 1.11.0-alpha.4.
      owner: Infrastructure Engineering
      due: 48h
      evidence: Source provides these versions as the fix for CVE-2026-55108.
  mitigation_plan:
    - priority: immediate
      action: Review all ComponentDefinition resources to verify remote Terraform sources are from trusted repositories.
      owner: Security Operations
      addresses: CVE-2026-55108
      evidence: Source identifies ComponentDefinition as the vector for remote repository configuration.
---

KubeVela versions 1.9.14, 1.10.9, and 1.11.0-alpha.4 are vulnerable to a denial-of-service (DoS) condition (CVE-2026-55108) within the `vela-core` controller. The vulnerability exists in the Terraform remote configuration loader, specifically within `pkg/controller/utils/capability.go`. The controller improperly validates file paths when processing remote git repositories defined in `ComponentDefinition` resources. By crafting a repository that includes a symlink (e.g., `variables.tf` pointing to `/dev/zero`), an attacker can force the `vela-core` controller to perform an unbounded read via `os.ReadFile`. Because the controller follows symlinks and does not verify file size or target location before reading, the process memory usage grows until the controller is terminated by the kernel OOM killer. This vulnerability affects the core control plane and can cause persistent crash loops if the malicious definition remains in the cluster.

## Attack Chain

1. Attacker gains authorization to create or update `core.oam.dev/v1beta1` `ComponentDefinition` resources in a target namespace.
2. Attacker initializes a git repository and creates a relative symbolic link named `variables.tf` or `main.tf` that resolves to `/dev/zero` (e.g., `ln -s ../../../../../../dev/zero variables.tf`).
3. Attacker pushes the repository to a location accessible by the KubeVela controller.
4. Attacker creates or updates a `ComponentDefinition` resource, setting `spec.schematic.terraform.type` to `remote` and providing the URL to the malicious repository.
5. The `vela-core` controller initiates a reconcile loop and clones the repository into its local cache.
6. The `GetTerraformConfigurationFromRemote` function executes `os.Stat` and `os.ReadFile` on the attacker-controlled symlink path.
7. The controller consumes system memory indefinitely while reading from the `/dev/zero` stream.
8. The `vela-core` controller process reaches the container memory limit and is terminated with an OOMKilled status, resulting in a denial-of-service for the KubeVela control plane.

## Impact

Successful exploitation results in a denial-of-service of the KubeVela control plane. The `vela-core` controller Pod enters a `CrashLoopBackOff` state, preventing the orchestration of application components across the cluster. If the controller lacks enforced memory limits, the unbounded read can place extreme pressure on node memory, potentially impacting other co-located workloads.

## Recommendation

1. Upgrade `vela-core` to the patched versions immediately: 1.9.14, 1.10.9, or 1.11.0-alpha.4.
2. Audit existing `ComponentDefinition` resources to identify and restrict `remote` Terraform repository URLs to trusted, internal-only sources.
3. Implement strict RBAC controls to limit which users can create or modify `ComponentDefinition` objects within the cluster.
4. Ensure Kubernetes memory limits are configured for the `vela-core` controller deployment to contain the impact of OOM conditions and prevent node-wide instability.
