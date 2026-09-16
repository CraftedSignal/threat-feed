---
title: Supply Chain Vulnerability in quay-builder-qemu via Mutable GitHub Action
slug: 2026-09-quay-builder-qemu-supply-chain
description: A supply chain vulnerability in quay-builder-qemu allows for remote code execution and credential theft due to the use of a mutable GitHub Action dependency.
date: "2026-09-16T23:52:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:red_hat:quay_builder_qemu:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - ci-cd
  - vulnerability
vendors:
  - Red Hat
products:
  - quay-builder-qemu
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: A remote attacker could exploit this by compromising the upstream Noelware/docker-manifest-action used in the release workflow.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allows the attacker to inject arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-85469
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85469
action_plan:
  priority: elevated
  owners:
    - DevSecOps
    - Security Engineering
  immediate_actions:
    - action: Pin all GitHub Actions in release workflows to immutable commit hashes.
      owner: DevSecOps
      due: 24h
      evidence: Source notes mutable branches as the primary vulnerability vector.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict GITHUB_TOKEN permissions in workflow YAML files.
      owner: DevSecOps
      addresses: CVE-2026-85469
      evidence: Workflow exposes default GitHub token, increasing severity.
---

CVE-2026-85469 describes a supply chain vulnerability affecting quay-builder-qemu, stemming from the inclusion of the third-party GitHub Action `Noelware/docker-manifest-action` in the project's release workflow. The workflow pins this dependency to a mutable branch rather than a specific immutable commit hash, creating a vector for dependency confusion or upstream compromise. 

If an attacker compromises the upstream Noelware repository, they can inject arbitrary malicious code that executes within the build environment. This process facilitates the exfiltration of sensitive registry credentials and the potential poisoning of container images produced by the build pipeline. Furthermore, the workflow configuration improperly exposes the default GitHub Actions token, which an attacker can leverage to further compromise the repository or associated infrastructure. This vulnerability highlights the significant risk posed by mutable dependencies in automated CI/CD pipelines.

## Impact

Successful exploitation allows an attacker to gain control over the build process, resulting in the theft of registry credentials and the injection of backdoored container images into the software supply chain. This impact extends to the integrity of any downstream systems or clients that deploy images built by the compromised pipeline.

## Recommendation

Prioritized actions for CI/CD pipeline security teams:
- Audit all GitHub Action workflows for dependencies pinned to mutable tags or branches.
- Pin all third-party GitHub Actions to specific, immutable SHA-256 commit hashes to prevent execution of unauthorized code.
- Audit workflow permissions to adhere to the principle of least privilege, specifically restricting access to secrets and the default GITHUB_TOKEN.
- Monitor CI/CD logs for unexpected network connections originating from build runners, particularly those targeting credential storage or external file hosting services.
