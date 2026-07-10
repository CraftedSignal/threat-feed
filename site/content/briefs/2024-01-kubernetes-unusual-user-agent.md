---
title: Kubernetes Unusual Decision by User Agent
slug: 2024-01-kubernetes-unusual-user-agent
description: This rule detects unusual request responses in Kubernetes audit logs by monitoring for anomalies in username and response annotations, potentially identifying unauthorized access or misconfigurations.
date: "2024-01-31T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - kubernetes
  - audit-logs
  - threat-detection
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/execution_unusual_request_response_by_user_agent.toml
rules:
  - title: Kubernetes Unusual User Agent Detected
    description: Detects unusual User Agents in Kubernetes audit logs
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - network_connection
      - kubernetes
  - title: Kubernetes Pod Creation with Suspicious User Agent
    description: Detects pod creation events with unusual user agents, indicating potential unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - process_creation
      - kubernetes
rules_count: 2
---

This detection rule identifies unusual request responses within Kubernetes environments by analyzing audit logs for anomalies in user agents and response annotations. The rule leverages the "new_terms" rule type, focusing on deviations from expected API request patterns typically made by system components or trusted users. By monitoring discrepancies in the `user_agent.original`, `kubernetes.audit.user.username`, and `kubernetes.audit.annotations.authorization_k8s_io/decision` fields, the rule aims to uncover potential unauthorized access attempts, misconfigured permissions, or malicious activities exploiting atypical user agent strings. This approach enhances the security posture of Kubernetes clusters by detecting subtle indicators of compromise that might otherwise go unnoticed. The rule is intended to be deployed in production environments where consistent user agent behavior is expected from trusted sources.

## Attack Chain

1.  Initial Access: An attacker gains initial access to the Kubernetes cluster through compromised credentials or a vulnerable application.
2.  Privilege Escalation: The attacker attempts to escalate privileges within the cluster, potentially using a service account with excessive permissions.
3.  Discovery: The attacker performs reconnaissance activities to map out the cluster's resources, including pods, services, and secrets. They use `kubectl` or similar tools to query the API server.
4.  Lateral Movement: Using the compromised credentials, the attacker moves laterally within the cluster, accessing different namespaces or nodes.
5.  Execution: The attacker executes malicious code within a pod or container, potentially deploying a reverse shell or a cryptominer. This is achieved by sending API requests to create or modify resources.
6.  Persistence: The attacker establishes persistence by creating a new service account with elevated privileges or by modifying existing deployments to include backdoors.
7.  Exfiltration (Potential): The attacker attempts to exfiltrate sensitive data from the cluster, such as secrets or configuration files.
8.  Impact: The attacker achieves their objectives, which could include data theft, denial of service, or complete control of the Kubernetes cluster.

## Impact

A successful attack could lead to unauthorized access to sensitive data, disruption of services, or complete compromise of the Kubernetes cluster. While the rule itself has a low severity, the underlying activities it detects can have severe consequences. The number of potential victims depends on the scope and criticality of the affected Kubernetes deployments. If exploited, attackers can gain control of containerized applications and infrastructure, leading to data breaches, financial losses, and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unusual Kubernetes API requests based on user agent (see the rule section).
*   Regularly review Kubernetes audit logs for unusual `user_agent.original` values, and correlate them with other security events.
*   Implement strict role-based access control (RBAC) policies to minimize the attack surface.
*   Configure monitoring and alerting for suspicious activity within the Kubernetes cluster.
*   Tune the Sigma rule exceptions to account for legitimate but infrequent user agents (see the rule's false positive analysis section).
