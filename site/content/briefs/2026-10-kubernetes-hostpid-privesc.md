---
title: Kubernetes Privilege Escalation via HostPID Namespace
slug: 2026-10-kubernetes-hostpid-privesc
description: Attackers can leverage misconfigured pods with hostPID enabled to gain visibility into host-level processes, facilitating container escape and privilege escalation to root on the underlying host node.
date: "2026-10-07T16:36:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - privilege-escalation
  - container-escape
  - cloud
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1610
    technique_name: Deploy Container
    evidence: The rule detects an attempt to create or modify a pod attached to the host PID namespace.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: When paired with ptrace this can be used to escalate privileges outside of the container.
    confidence_band: high
references:
  - https://research.nccgroup.com/2021/11/10/detection-engineering-for-kubernetes-clusters/#part3-kubernetes-detections
  - https://kubernetes.io/docs/concepts/security/pod-security-admission/
  - https://bishopfox.com/blog/kubernetes-pod-privilege-escalation
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_pod_created_with_hostpid.toml
rules:
  - title: Detect Kubernetes Pod Created With HostPID
    description: Detects creation or modification of pods with hostPID set to true, which can facilitate container escape and host-level privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1610
      - T1611
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor for HostPID pod deployments
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit logic for detecting HostPID misconfiguration
  hunt_leads:
    - lead: 'Search for existing pods with hostPID: true in the environment'
      technique_id: T1611
      data_needed:
        - Kubernetes configuration metadata
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: HostPID configuration is a high-risk misconfiguration regardless of when it was applied
  mitigation_plan:
    - priority: short_term
      action: Implement Pod Security Admission to restrict HostPID usage
      owner: IT Operations
      addresses: HostPID privilege escalation
      evidence: Kubernetes security best practices
---

The Kubernetes hostPID namespace configuration allows a pod to share the process ID space with the underlying host node. While this capability is sometimes utilized for legitimate diagnostic or monitoring tasks, it introduces a significant security risk when unauthorized or compromised pods are deployed with this flag. By gaining access to host processes, an attacker can enumerate running services, identify sensitive configuration files, or inject code into host processes. When this misconfiguration is combined with privileged container status or capabilities like ptrace, it enables an attacker to escape the container environment, enter the host init system (PID 1), and escalate privileges to root on the node. This threat vector is critical in multi-tenant or shared-responsibility cluster environments where workload isolation is paramount. Defenders must monitor Kubernetes API audit logs for the creation or modification of pods that include the 'hostPID: true' specification.

## Attack Chain

1. Attacker gains initial access to the Kubernetes cluster via compromised service account credentials or a vulnerable web application.
2. Attacker prepares a malicious container image designed for host process interaction.
3. Attacker uses the Kubernetes API to create or patch a pod specification, setting 'hostPID' to true.
4. The Kubernetes scheduler successfully deploys the malicious pod on a worker node.
5. Attacker executes a shell within the container to gain access to the host's PID namespace.
6. Attacker leverages ptrace or other process manipulation techniques to interact with host-level processes (PID 1).
7. Attacker executes malicious commands as root on the host node, effectively escaping the container boundary.

## Impact

Successful exploitation results in full host node compromise, allowing the attacker to access sensitive host files, modify system configurations, pivot to other nodes in the cluster, or exfiltrate data from all containers running on the affected node.

## Recommendation

Prioritize auditing cluster configurations and implementing admission control policies to restrict the use of the hostPID namespace to only verified, necessary system workloads.
- Deploy the provided detection rule to monitor for unauthorized pods using hostPID.
- Audit Kubernetes API audit logs (logs-kubernetes.audit_logs-*) for any pod creation or update events where hostPID is enabled.
- Implement Kubernetes Pod Security Admission (PSA) policies to prevent the deployment of pods with hostPID enabled in production namespaces.
- Review and prune high-privilege service account permissions to prevent unauthorized pod creation.
