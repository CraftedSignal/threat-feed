---
title: Detection of Unauthorized Kubernetes Secret Access via Suspicious User Agents
slug: 2026-08-k8s-secret-access
description: This brief details a detection strategy for identifying unauthorized Kubernetes Secret retrieval via non-standard HTTP clients and scripting runtimes commonly used in credential exfiltration.
date: "2026-08-24T15:47:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - kubernetes
  - cloud-security
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The rule matches Kubernetes audit events for secret get/list where user_agent.original matches a small allowlist of suspicious patterns.
    confidence_band: high
rules:
  - title: Detect Kubernetes Secret Access via Suspicious User Agents
    description: Detects read access to Kubernetes Secrets (get/list) using suspicious User-Agent strings indicative of scripting runtimes or offensive security tooling.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - webserver
      - kubernetes
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule and establish a baseline of known automation User-Agents.
      owner: Detection Engineering
      due: 48h
      evidence: Required for reducing false positives in production environments.
  mitigation_plan:
    - priority: medium_term
      action: Tighten RBAC policies to restrict 'get' and 'list' permissions on secrets to specific, audited service accounts.
      owner: IT Operations
      addresses: T1552.007
      evidence: Best practice for securing Kubernetes Secrets management.
---

This threat detection intelligence focuses on identifying credential access attempts targeting Kubernetes Secrets. Attackers frequently utilize minimal HTTP tooling, generic scripting runtimes, and offensive security-oriented binaries to interact with the Kubernetes API to exfiltrate sensitive configuration data, service account tokens, and TLS bundles. The detection logic centers on monitoring Kubernetes API server audit logs for successful 'get' or 'list' operations on 'secrets' resources, filtered by User-Agent strings. Legitimate in-cluster automation is typically characterized by stable, purpose-specific User-Agent strings (e.g., official client-go variants), whereas attacker-leaning activity is characterized by generic fingerprints such as 'curl', 'python', 'node', or distribution-tagged strings associated with platforms like Kali Linux. Distinguishing this activity requires baselining internal CI/CD pipelines and service account behavior.

## Impact

Successful exfiltration of Kubernetes Secrets can lead to full cluster compromise. Secrets frequently contain critical credentials including database passwords, API keys, cloud provider IAM service account tokens, and TLS certificates. If compromised, an attacker can leverage these to escalate privileges, persist in the environment, move laterally to cloud infrastructure, or gain unauthorized access to backend services and external third-party systems managed by the cluster.

## Recommendation

Prioritized actions for detection and response:

- Deploy the provided Sigma rule (or equivalent SIEM detection) to monitor Kubernetes audit logs for suspicious User-Agent strings during secret access.
- Establish a baseline for all known, authorized in-cluster automation (CI/CD controllers, GitOps agents) to reduce false positives during rule tuning.
- Investigate any hits by validating the 'user.name' against organizational identity providers and reviewing the 'source.ip' for unexpected origin points.
- Upon confirmation of unauthorized access, immediately rotate the exposed credentials, revoke the associated identity tokens, and audit the scope of RBAC roles assigned to the compromised principal.
