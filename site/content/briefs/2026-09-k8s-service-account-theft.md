---
title: Kubernetes Service Account Token Theft and API Abuse
slug: 2026-09-k8s-service-account-theft
description: Adversaries are targeting Kubernetes pods to steal service account tokens and certificates, subsequently using them for cluster-wide reconnaissance and lateral movement.
date: "2026-09-18T19:15:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - cloud-security
  - credential-theft
  - lateral-movement
vendors:
  - Kubernetes
products:
  - Kubernetes
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries gain initial access to a pod (e.g., via kubectl exec).
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers typically exec into a container, read sensitive files at /var/run/secrets/kubernetes.io/serviceaccount/.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: These requests are often used to enumerate the Kubernetes API server or other resources within the cluster.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An adversary may need to access the service account token or certificate to gain access to the Kubernetes API server or other resources within the cluster.
    confidence_band: high
rules:
  - title: Detect Service Account Token or Certificate Access Followed by Kubernetes API Request
    description: Detects interactive access to service account secrets followed by a Kubernetes API request from the same pod, indicating potential credential harvesting and lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - execution
    techniques:
      - T1059.004
      - T1552.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Platform Engineering
  immediate_actions:
    - action: Review and deploy the provided EQL rule to correlate container and audit logs.
      owner: Detection Engineering
      due: 72h
      evidence: Rule allows detection of credential theft followed by API abuse.
  hunt_leads:
    - lead: Identify pods that recently performed both shell execution and subsequent API requests.
      technique_id: T1059.004
      data_needed:
        - Audit logs
        - Defend for Containers file access events
      priority: high
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: immediate
      action: 'Set automountServiceAccountToken: false on all service accounts that do not require API access.'
      owner: Platform Engineering
      addresses: General credential theft risk
---

Adversaries are actively targeting Kubernetes environments by exploiting interactive container sessions to harvest sensitive service account credentials. Attackers gain initial access to a pod (e.g., via `kubectl exec`) and proceed to read the service account token (`/var/run/secrets/kubernetes.io/serviceaccount/token`) and the CA certificate (`ca.crt`). These artifacts provide the necessary credentials to authenticate to the Kubernetes API server as the pod's service account. Once authenticated, the attacker performs unauthorized API requests to conduct cluster reconnaissance, exfiltrate secrets, or attempt lateral movement by escalating privileges or pivoting to other nodes. This activity is notable because it leverages native, legitimate application paths to bypass traditional perimeter security, making correlation between container-level file access and cluster-level audit logs essential for detection.

## Attack Chain

1. An attacker gains initial interactive access to a container, often through a compromised application or misconfigured pod (`kubectl exec`).
2. The attacker performs a file read operation on the service account token located at `/var/run/secrets/kubernetes.io/serviceaccount/token`.
3. The attacker reads the associated CA certificate at `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` to facilitate TLS communication.
4. Using the harvested token, the attacker interacts with the Kubernetes API server, typically via `curl`, `kubectl`, or custom scripts.
5. The API server processes the request, authenticating the attacker as the pod's service account.
6. The attacker performs reconnaissance, such as listing pods, secrets, or nodes within the cluster.
7. If the service account possesses excessive RBAC permissions, the attacker pivots to other namespaces, modifies RoleBindings, or creates privileged pods to compromise the wider cluster.

## Impact

Successful exploitation allows an adversary to impersonate a service account, potentially leading to full cluster compromise. Depending on the service account's RBAC scope, this can result in the exfiltration of sensitive configuration secrets, unauthorized deployment of malicious containers, or total administrative takeover of the Kubernetes environment.

## Recommendation

1. Deploy the provided detection logic to correlate container file access events with Kubernetes audit logs.
2. Implement a policy of least privilege by scoping service account RBAC bindings strictly to the resources required by the application.
3. Disable `automountServiceAccountToken` on all pods that do not require interaction with the Kubernetes API.
4. Enforce Pod Security Admission policies to restrict or eliminate the use of interactive shells (`exec`/`attach`) within production containers.
5. Monitor Kubernetes audit logs specifically for anomalous verbs or user-agents associated with service accounts, especially those requesting secrets or creating pods in foreign namespaces.
