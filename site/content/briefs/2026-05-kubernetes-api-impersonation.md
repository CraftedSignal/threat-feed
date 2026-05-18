---
title: Kubernetes API Request Impersonating Privileged Identity
slug: 2026-05-kubernetes-api-impersonation
description: Detects Kubernetes API requests where a user is impersonating a privileged cluster identity such as system:kube-controller-manager, system:admin, system:anonymous, or a member of the system:masters group, potentially leading to privilege escalation and unauthorized access.
date: "2026-05-18T11:25:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - privilege-escalation
  - defense-evasion
vendors:
  - Elastic
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1134
    technique_name: Access Token Manipulation
references:
  - https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation
  - https://attack.mitre.org/techniques/T1134/
  - https://attack.mitre.org/tactics/TA0004/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Detect Kubernetes API Request Impersonating Privileged Identity
    description: Detects Kubernetes API requests where a user is impersonating a privileged cluster identity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1134
    data_sources:
      - webserver
  - title: Detect Kubernetes API Request Impersonating Privileged Identity - Non-Standard User Agent
    description: Detects Kubernetes API requests impersonating privileged identities with a non-standard user agent.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1134
    data_sources:
      - webserver
rules_count: 2
---

This detection rule identifies Kubernetes API requests where a user is impersonating a highly privileged cluster identity. The targeted identities include `system:kube-controller-manager`, `system:admin`, `system:anonymous`, and members of the `system:masters` group. Successful impersonation of these identities grants broad cluster-wide permissions, enabling attackers to access all secrets, create tokens for any service account, schedule pods on any node, and modify RBAC policies. Exploitation of this vulnerability can provide attackers with cluster-admin equivalent access or access to all secrets in every namespace. This can lead to significant compromise within the Kubernetes environment.

## Attack Chain

1. An attacker gains initial access to the Kubernetes cluster, possibly through compromised credentials or a vulnerable application.
2. The attacker crafts a malicious Kubernetes API request.
3. The attacker includes impersonation headers in the API request, targeting a privileged identity such as `system:kube-controller-manager` or a member of `system:masters`.
4. The Kubernetes API server receives the request and, if RBAC checks are insufficient or bypassed, allows the impersonation.
5. The attacker, now impersonating the privileged identity, issues further API requests to access sensitive resources like secrets or to create service account tokens.
6. The attacker uses the stolen secrets or created tokens for lateral movement within the cluster.
7. The attacker escalates privileges and gains unauthorized control over the cluster.

## Impact

Successful exploitation allows the attacker to escalate privileges within the Kubernetes cluster, potentially leading to full cluster control. The attacker can access sensitive data such as secrets, modify RBAC policies, and deploy malicious workloads. This can result in data breaches, service disruptions, and long-term compromise of the cluster and its resources.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious Kubernetes API requests involving privileged identity impersonation.
*   Review and tighten RBAC permissions within the Kubernetes cluster, especially for impersonation rights.
*   Monitor Kubernetes audit logs for unexpected impersonation activity, focusing on the user.name and kubernetes.audit.impersonatedUser fields.
*   Implement strict network segmentation to limit the blast radius of compromised nodes or containers.
*   Use Kubernetes admission controllers to enforce policies that prevent unauthorized impersonation attempts.
