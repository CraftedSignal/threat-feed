---
brief_id: brief-2026-10-20-argo-cd-rce
event_id: brief-2026-10-20-argo-cd-rce
revision: 2
activity_at: "2026-10-20T20:45:17Z"
revision_history:
  - revision: 2
    at: "2026-10-20T20:45:17Z"
    checksum: sha256:85e7225393d0438c287239bcca9869b32883e2c6683ed91633be9689064f6e00
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-113709&utm_source=rss&utm_medium=rss
title: 'Argo CD: Arbitrary code execution via Helm downloader plugin (CVE-2026-113709)'
slug: 2026-10-argo-cd-rce
description: Argo CD versions 2.1.0 through 3.6.0-rc1 are vulnerable to arbitrary code execution if --enable-helm is used, allowing attackers to inject a malicious Helm plugin via repository-controlled configuration.
date: "2026-10-20T19:45:34Z"
lastmod: "2026-10-20T20:44:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: verified against NVD
cpes:
  - cpe:2.3:a:cloud_native_computing_foundation:argo_cd:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-113709&utm_source=rss&utm_medium=rss
tags:
  - remote-code-execution
  - gitops
  - kubernetes
vendors:
  - Cloud Native Computing Foundation
products:
  - Argo CD (2.1.0 to <3.3.15, 3.4.0 to <3.4.10, 3.5.0 to <3.5.4, 3.6.0-rc1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can commit the Kustomization and plugin to a Git repository that an Application builds or upload the files through POST /api/v1/applications/manifestsWithFiles.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: Helm automatically loads a downloader plugin... and executes its program inside argocd-repo-server when a helmCharts repository URL uses the plugin's protocol.
    confidence_band: high
cves:
  - id: CVE-2026-113709
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113709
  - https://sploitus.com/exploit?id=CVE-2026-113709&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Argo CD to version 3.3.15, 3.4.10, 3.5.4, or 3.6.0-rc2.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-113709 vendor patch availability
  mitigation_plan:
    - priority: immediate
      action: Disable --enable-helm flag in Kustomize build configuration if not strictly required.
      owner: IT Operations
      addresses: CVE-2026-113709
      evidence: The upload path requires only Application get permission... Both delivery paths require prior operator enablement of --enable-helm.
updates:
  - at: "2026-10-20T20:44:37Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-113709&utm_source=rss&utm_medium=rss
---

Argo CD, a GitOps continuous delivery tool, contains a vulnerability (CVE-2026-113709) that enables remote code execution within the 'argocd-repo-server' component. This vulnerability is present in versions 2.1.0 through 3.3.15, 3.4.10, 3.5.4, and 3.6.0-rc2. The flaw occurs when the '--enable-helm' flag is enabled for Kustomize builds. An attacker can influence the 'helmGlobals.configHome' setting to point to a directory controlled by a Git repository or via the 'manifestsWithFiles' API endpoint.

Because Helm automatically loads downloader plugins from the '&lt;configHome>/.data/plugins' directory without additional installation steps, an attacker can place a malicious executable in this path. When the 'argocd-repo-server' attempts to process a chart using a protocol handled by the plugin, it executes the payload under the context of the 'repo-server' user. This allows for the exfiltration of repository credentials and sensitive environment data. This exploit requires only 'Application get' permissions.

## Attack Chain

1. The operator enables '--enable-helm' within the Argo CD Kustomize build configuration.
2. The attacker gains read access to an existing Application, or the ability to commit to a Git repository used by an Application.
3. The attacker crafts a malicious Helm downloader plugin.
4. The attacker defines a Kustomization file that sets 'helmGlobals.configHome' to a repository-controlled directory.
5. The attacker commits the plugin and configuration to a Git repository, or uploads the files via the 'POST /api/v1/applications/manifestsWithFiles' endpoint.
6. The 'argocd-repo-server' performs a build operation, causing Helm to identify and load the malicious plugin from the attacker-controlled directory.
7. The Helm plugin executes as the 'repo-server' user during the manifest generation process.
8. The attacker exfiltrates sensitive repository credentials or process-accessible data from the 'argocd-repo-server' environment.

## Impact

Successful exploitation allows for complete compromise of the 'argocd-repo-server' execution context. Attackers can steal repository credentials, access secret management data, and potentially pivot into the broader Kubernetes cluster environment, depending on the service account permissions granted to the Argo CD controller.

## Recommendation

1. Upgrade to the patched versions of Argo CD: 3.3.15, 3.4.10, 3.5.4, or 3.6.0-rc2 immediately.
2. Review deployments for the use of the '--enable-helm' flag; disable this flag if Helm plugin functionality is not required for Kustomize builds.
3. Restrict 'Application get' permissions to minimize the exposure of the 'manifestsWithFiles' API endpoint.
