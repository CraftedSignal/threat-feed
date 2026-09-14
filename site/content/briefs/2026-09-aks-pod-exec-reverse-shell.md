---
title: Detection of Unauthorized Reverse Shells via Azure AKS Pod Exec
slug: 2026-09-aks-pod-exec-reverse-shell
description: Attackers are exploiting the 'kubectl exec' capability in Azure Kubernetes Service to establish unauthorized reverse or bind shells by injecting malicious command-line patterns into pod execution requests.
date: "2026-09-14T18:54:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - kubernetes
  - azure
  - execution
  - command-and-control
vendors:
  - Microsoft
products:
  - Azure Kubernetes Service (AKS)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule detects interactive invocation of common shells and language-based socket one-liners used for post-exploitation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: The rule targets unauthorized pods/exec calls which is a core container administration command.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1095
    technique_name: Non-Application Layer Protocol
    evidence: Detection of /dev/tcp, /dev/udp, and netcat-style listeners indicates non-standard C2 communication.
    confidence_band: high
references:
  - https://microsoft.github.io/Threat-Matrix-for-Kubernetes/
  - https://kubernetes.io/docs/reference/access-authn-authz/authorization/
  - https://cloudsecdocs.com/containers/offensive/attacks/techniques/reverse_shell/
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Cloud Security Operations
  immediate_actions:
    - action: Deploy ESQL detection for pod exec shell idioms in AKS logs.
      owner: Detection Engineering
      due: 48h
      evidence: Source provided ESQL detection rule.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict RBAC 'pods/exec' permissions for all service accounts.
      owner: Cloud Security Operations
      addresses: T1609
      evidence: Source recommends hardening RBAC to least privilege.
---

Security researchers have identified a recurring pattern where attackers abuse the Kubernetes 'pods/exec' subresource within Azure Kubernetes Service (AKS) to bypass container isolation and achieve persistent, interactive control. By injecting specialized command strings - such as language-based socket idioms, netcat/socat listeners, or shell redirection via /dev/tcp - threat actors can initiate a reverse shell from within the cluster. This technique leverages legitimate administrative functionality, making it difficult to distinguish from authorized troubleshooting. The attack is most frequently observed through kube-audit logs, specifically targeting the requestURI parameter during exec calls. Defenders must distinguish between administrative 'kubectl' sessions and automated exploitation attempts that manifest as anomalous command-line payloads.

## Attack Chain

1. Attacker gains access to a compromised identity (e.g., via stolen kubeconfig or service account token) with 'pods/exec' permissions.
2. Attacker probes the environment to identify accessible namespaces, pods, and containers using 'kubectl get pods'.
3. Attacker crafts an 'exec' request to a target pod, embedding a reverse shell payload in the 'command' query parameter.
4. The command is transmitted to the AKS API server as a URL-encoded string.
5. The API server authenticates the session and initiates the stream to the target pod.
6. The container spawns the specified shell process, which executes the redirection logic (e.g., 'bash -i >& /dev/tcp/...').
7. A bi-directional stream is established between the container and the attacker's listener, granting interactive command execution.

## Impact

Successful exploitation allows for full command execution within the context of the target container. This grants the attacker potential access to sensitive environment variables, service account tokens (often used for broader cluster escalation), and internal network resources. Unauthorized access can lead to lateral movement, data exfiltration, or the deployment of additional malicious container images.

## Recommendation

1. Deploy the ESQL detection logic provided below to monitor for suspicious command idioms in AKS 'pods/exec' events within the Azure 'kube-audit' log stream.
2. Baseline authorized administrative 'kubectl' usage patterns and implement strict RBAC policies to limit the 'pods/exec' verb to specific, verified human identities only.
3. Audit and restrict the use of highly permissive 'system:serviceaccount' entities, specifically monitoring for anomalous exec behavior originating from automated accounts.
4. Integrate Azure platform logs into a SIEM for real-time monitoring of Microsoft.ContainerService/managedClusters/diagnosticLogs/Read events.
