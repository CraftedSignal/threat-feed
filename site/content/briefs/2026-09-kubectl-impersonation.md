---
title: Potential Kubernetes Impersonation via Kubectl Flags
slug: 2026-09-kubectl-impersonation
description: Adversaries may perform unauthorized impersonation within Kubernetes clusters by executing the 'kubectl' command-line tool with sensitive flags like '--as' or '--token' to escalate privileges or bypass access controls.
date: "2026-09-18T19:11:10Z"
lastmod: "2026-09-19T13:11:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - kubernetes
  - container-security
vendors:
  - Kubernetes
products:
  - kubectl
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries may perform unauthorized impersonation within Kubernetes clusters by executing the 'kubectl' command-line tool with specific flags.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: This technique allows attackers to leverage valid accounts or stolen authentication materials to escalate privileges.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_potential_kubectl_impersonation.toml
rules:
  - title: Detect Potential Impersonation Attempt via Kubectl
    description: Detects kubectl process execution with impersonation flags such as --as, --token, or --kubeconfig, often initiated from suspicious parent processes or locations.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1078
      - T1550.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy kubectl impersonation detection rule
      owner: Detection Engineering
      due: 48h
      evidence: Rule logic provided in brief
  hunt_leads:
    - lead: Search for historical process starts of kubectl with --as, --token, or --kubeconfig arguments
      technique_id: T1078
      data_needed:
        - process_creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known technique for Kubernetes impersonation
  mitigation_plan:
    - priority: medium
      action: Audit Kubernetes RBAC permissions for 'impersonate' verb
      owner: IT Operations
      addresses: T1078
      evidence: Source highlights impersonation as a risk
updates:
  - at: "2026-09-19T13:11:31Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_potential_kubectl_impersonation.toml
---

Adversaries targeting containerized environments may exploit the 'kubectl' command-line interface to perform unauthorized impersonation. By utilizing specific flags such as '--as', '--as-group', '--as-uid', '--token', or '--kubeconfig', an attacker can assume the identity of another user or service account within a Kubernetes cluster. This technique allows adversaries to leverage valid accounts or stolen authentication materials to escalate privileges, bypass existing access controls, and move laterally across the cluster. This activity is often detected when 'kubectl' is executed from unconventional or high-risk locations, such as temporary directories ('/tmp', '/var/tmp') or via shell scripts, which may indicate that the command is being invoked by automated malicious payloads rather than an interactive administrator session. Organizations should monitor process execution logs for these specific flags to identify potentially malicious cluster interactions.

## Attack Chain

1. An adversary gains initial access to a Linux or macOS container host.
2. The attacker discovers existing 'kubeconfig' files or sensitive tokens on the filesystem.
3. The attacker locates the 'kubectl' binary on the host or downloads a malicious version.
4. The attacker initiates 'kubectl' execution from a suspicious location like '/tmp/' or via an automated shell script.
5. The attacker executes 'kubectl' with impersonation flags (e.g., --as, --token) to assume elevated privileges of a target service account.
6. The adversary uses the impersonated identity to query or modify cluster resources.
7. The objective is to achieve unauthorized persistence, exfiltrate sensitive cluster data, or deploy malicious pods.

## Impact

Successful impersonation in a Kubernetes environment can result in full cluster compromise, unauthorized access to sensitive application secrets, data exfiltration from persistent volumes, and the deployment of persistent malicious workloads. This threat is particularly significant in environments where role-based access control (RBAC) relies on service account tokens that are vulnerable to theft.

## Recommendation

1. Deploy the provided detection rule to identify 'kubectl' executions involving impersonation flags.
2. Audit Kubernetes RBAC policies to ensure that the "impersonate" verb is strictly limited to authorized administrative service accounts.
3. Implement strict filesystem integrity monitoring on nodes to detect unauthorized execution from temporary directories ('/tmp', '/var/tmp', '/dev/shm').
4. Revoke and rotate credentials associated with identified impersonation events if they do not align with known CI/CD pipeline activity.
5. Enable container-aware logging to correlate 'kubectl' process executions with specific Kubernetes API server audit logs.
