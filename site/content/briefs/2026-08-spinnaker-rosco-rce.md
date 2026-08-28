---
title: Remote Code Execution in Spinnaker rosco-manifests via Kustomize
slug: 2026-08-spinnaker-rosco-rce
description: The Spinnaker rosco-manifests package is vulnerable to remote code execution (RCE) via improper YAML processing during Kustomize bake operations, allowing attackers to execute arbitrary code on rosco pods.
date: "2026-08-28T21:15:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:linuxfoundation:spinnaker:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - ci-cd
  - spinnaker
vendors:
  - Spinnaker
products:
  - rosco-manifests (< 2025.3.4, 2025.4.0-2025.4.3, 2026.0.0-2026.0.2, 2026.1.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This can lead to RCE type exploits on the rosco pods when doing kustomize bakes.
    confidence_band: high
cves:
  - id: CVE-2026-55175
    cvss: 7.5
    epss: 0.01057
references:
  - https://github.com/advisories/GHSA-p68j-q7hf-3qcp
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55175
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Disable Kustomize bake operations in Spinnaker as a temporary mitigation
      owner: Security Engineering
      due: 24h
      evidence: The simple solution is to block kustomize operations and instead use another provider.
  mitigation_plan:
    - priority: immediate
      action: Upgrade rosco-manifests to non-vulnerable versions as specified in the advisory
      owner: IT Operations
      addresses: CVE-2026-55175
      evidence: Affected packages list identifies specific fixed versions.
---

Spinnaker's rosco-manifests package is susceptible to a high-severity remote code execution (RCE) vulnerability, tracked as CVE-2026-55175. The issue arises from improper YAML processing when the system performs Kustomize bake operations. An attacker capable of influencing the Kustomize input can trigger unsafe tag processing, resulting in the execution of arbitrary commands within the context of the rosco pods. This vulnerability is specific to the Kustomize provider within Spinnaker. Defenders should prioritize updating to the fixed versions or disabling Kustomize bake operations until patches can be applied. The vulnerability affects multiple versions of rosco-manifests across the 2025 and 2026 release cycles.

## Impact

Successful exploitation allows for remote code execution on the rosco pod, potentially leading to unauthorized system access, data exfiltration, or further compromise of the Spinnaker deployment environment. The vulnerability impacts organizations using Spinnaker for continuous delivery and CI/CD orchestration, particularly those utilizing Kustomize for manifest generation.

## Recommendation

- Upgrade rosco-manifests to versions 2025.3.4, 2025.4.4, 2026.0.3, 2026.1.1, or later to remediate CVE-2026-55175.
- Disable Kustomize bake operations in the Spinnaker configuration as an immediate workaround if patching cannot be performed immediately.
- Audit logs for the rosco-manifests service to identify anomalous Kustomize bake requests or suspicious process execution originating from the rosco pod.
