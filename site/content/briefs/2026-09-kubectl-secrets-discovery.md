---
title: Kubernetes Secret Discovery via Kubectl
slug: 2026-09-kubectl-secrets-discovery
description: Adversaries may use the kubectl command-line tool to enumerate sensitive secret objects across all Kubernetes namespaces to facilitate credential theft, privilege escalation, or lateral movement.
date: "2026-09-18T19:13:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - container
  - discovery
  - credential-access
vendors:
  - Kubernetes
products:
  - Kubernetes
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: Adversaries may use this command to identify accessible secrets in multiple namespaces, aiding credential discovery.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers may use this command to identify accessible secrets in multiple namespaces, aiding credential discovery.
    confidence_band: high
rules:
  - title: Detect Kubectl Secrets Enumeration Across All Namespaces
    description: Detects the use of the kubectl command to enumerate secrets across all namespaces, a technique often used for credential discovery.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552
      - T1613
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule for kubectl secret enumeration
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command arguments for detection.
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict cluster-wide RBAC permissions
      owner: IT Operations
      addresses: T1613
      evidence: Principle of least privilege reduces the impact of secret discovery.
---

Adversaries targeting Kubernetes environments frequently attempt to discover sensitive information stored within the cluster. A common technique involves using the `kubectl` command-line utility to query for secret resources across the entire cluster using global flags. By executing `kubectl get secrets --all-namespaces` or the abbreviated `kubectl get secrets -A`, an attacker can gain visibility into secrets across multiple namespaces, even if their current context is restricted. 

This activity is a high-signal indicator of unauthorized reconnaissance. Defenders must differentiate this activity from legitimate administrative, CI/CD, or compliance-related resource inventory. Because these secrets often contain API keys, database credentials, or TLS certificates, successful discovery is a critical precursor to further compromise, such as privilege escalation or exfiltration of sensitive application data. Defenders should focus on process-level command-line monitoring and correlate findings with Kubernetes API audit logs.

## Impact

Successful secret discovery can lead to the exposure of highly sensitive credentials, enabling an attacker to escalate privileges within the cluster, move laterally to other pods or services, or exfiltrate data from external systems accessed via the discovered secrets. The damage depends on the sensitivity of the stored secrets; in worst-case scenarios, it provides the attacker with administrative control over the entire cluster or connected cloud infrastructure.

## Recommendation

- Deploy the detection rule below to identify `kubectl` execution with broad secret discovery flags.
- Baseline existing administrative, CI/CD, and compliance tool execution patterns to reduce noise from authorized workflows.
- Enable Kubernetes API audit logging to correlate `kubectl` execution with specific secret read events.
- Review and tighten Role-Based Access Control (RBAC) permissions to ensure that service accounts and users operate under the principle of least privilege regarding namespace and resource visibility.
- If unauthorized discovery is detected, rotate any secrets that were accessible to the compromised identity and audit surrounding activity for signs of credential usage or persistence.
