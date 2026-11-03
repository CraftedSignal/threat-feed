---
brief_id: brief-2026-11-03-kubelet-access
event_id: brief-2026-11-03-kubelet-access
revision: 1
activity_at: "2026-11-03T21:48:23Z"
title: 'Kubernetes: Potential unauthorized Kubelet API access from containers'
slug: 2026-11-kubelet-access
description: Adversaries are leveraging compromised containers to interact directly with the Kubelet API on ports 10250 and 10255 to perform enumeration, log extraction, and remote command execution.
date: "2026-11-03T21:48:23Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - kubernetes
  - container
  - discovery
  - lateral-movement
  - execution
vendors:
  - Kubernetes
products:
  - Kubelet
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: This detection flags an interactive process started inside a Linux container that includes an HTTP request targeting the Kubelet API on port 10250
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: Attackers use direct Kubelet access to enumerate pods, fetch logs, or run commands that can lead to broader cluster access
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: These requests are often used to enumerate or execute commands... and may indicate an attempt to move laterally within the cluster.
    confidence_band: high
references:
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#kubelet-api
  - https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster
  - https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/execution_potential_direct_kubelet_access_via_process_args.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Platform Security
  immediate_actions:
    - action: Deploy process-creation monitoring to identify curl or wget requests to Kubelet ports
      owner: Detection Engineering
      due: 48h
      evidence: Source detection rule definition
  hunt_leads:
    - lead: Search for shell process execution inside containers involving arguments with destination ports 10250 or 10255
      technique_id: T1059.004
      data_needed:
        - Linux process audit logs
        - Container process execution telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This detection flags an interactive process started inside a Linux container that includes an HTTP request targeting the Kubelet API
  mitigation_plan:
    - priority: immediate
      action: Implement network policies to restrict container egress to Kubelet ports 10250 and 10255
      owner: Platform Security
      addresses: Unauthorized Kubelet access
      evidence: Harden by enforcing Kubelet authentication/authorization and implement network controls
---

Adversaries may attempt to interact with the Kubelet API from within a container to gain visibility into the node, enumerate pods, or execute commands on the host. This behavior is typically observed when command-line utilities such as curl or wget are invoked from an interactive container shell to reach the Kubelet API port. Unauthorized access to the Kubelet API facilitates lateral movement and potential privilege escalation within a Kubernetes cluster.

## Attack Chain

1. Initial access to a container via exploitation or misconfiguration.
2. Execution of an interactive shell within the container.
3. Reconnaissance of the local node or cluster network to identify Kubelet API endpoints.
4. Execution of HTTP/WSS requests directed at the node Kubelet API (port 10250 or 10255).
5. Enumeration of cluster resources, pod logs, or execution of commands via API endpoints such as /exec, /run, or /containerLogs.
6. Escalation of privileges or lateral movement to other cluster resources.

## Impact

Successful unauthorized access to the Kubelet API can lead to full cluster compromise, unauthorized pod execution, and exposure of sensitive container logs or environment variables.

## Recommendation

- Deploy the provided detection rule to monitor for process executions involving Kubelet port access from containers.
- Implement network policies to block egress traffic from container namespaces to node-local Kubelet ports (10250/10255).
- Harden Kubelet configurations by disabling anonymous access and requiring authenticated, authorized webhook requests.
- Remove administrative tooling (e.g., curl, wget, shell access) from production container images.
- Rotate sensitive credentials, including service account tokens and client certificates, if unauthorized Kubelet API requests are detected.
