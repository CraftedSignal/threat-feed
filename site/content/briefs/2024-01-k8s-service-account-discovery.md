---
title: Kubernetes Denied Service Account Request via Unusual User Agent
slug: 2024-01-k8s-service-account-discovery
description: A Kubernetes service account made an unauthorized request to the API server using an unusual user agent, potentially indicating compromised credentials used for resource discovery or lateral movement.
date: "2024-01-19T17:30:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - kubernetes
  - service-account
  - discovery
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
references:
  - https://research.nccgroup.com/2021/11/10/detection-engineering-for-kubernetes-clusters/#part3-kubernetes-detections
  - https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens
rules:
  - title: Kubernetes Unusual Service Account User Agent
    description: Detects unauthorized requests from Kubernetes service accounts with unusual user agents.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1613
    data_sources:
      - network_connection
      - kubernetes
  - title: Kubernetes Forbid Events with User Agent
    description: Detects forbid events in kubernetes audit logs with user agent
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1613
    data_sources:
      - file_event
      - kubernetes
rules_count: 2
---

This detection rule identifies suspicious activity within Kubernetes clusters where a service account makes an unauthorized request to the API server, utilizing a user agent that deviates from established patterns. Kubernetes service accounts typically exhibit predictable behavior, and deviations, especially unauthorized requests, can indicate compromised credentials or cluster misconfigurations. Attackers may exploit such access to discover resources within the cluster, facilitating further movement or execution. The rule aims to detect these anomalies by flagging unauthorized API requests from service accounts associated with unusual user agents, potentially signaling security breaches or misconfigurations. The monitored behavior is when an audit log is created by a service account that is denied with an unusual user agent.

## Attack Chain

1.  An attacker gains unauthorized access to a Kubernetes service account's credentials.
2.  The attacker uses these credentials to send a request to the Kubernetes API server.
3.  The request targets sensitive information or resources within the cluster.
4.  The API server denies the request due to insufficient privileges or policy restrictions.
5.  The request is logged in the Kubernetes audit logs, including the user agent used.
6.  A detection rule identifies the unauthorized request based on the service account and user agent.
7.  The security team investigates the alert, looking for further malicious activity.
8.  The attacker's goal is to enumerate resources and potentially gain further access within the Kubernetes environment.

## Impact

A successful attack could allow unauthorized enumeration of Kubernetes resources. The impact is potentially lower due to the request being denied, but the attempt indicates a potential compromise. The blast radius depends on the permissions and access the compromised service account has within the cluster. The primary sector impacted is cloud infrastructure.

## Recommendation

*   Deploy the Sigma rule `Kubernetes Unusual Service Account User Agent` to your SIEM and tune for your environment to detect unusual user agents (rules).
*   Investigate alerts triggered by the `Kubernetes Unusual Service Account User Agent` Sigma rule by reviewing the specific service account involved to determine if it was used legitimately or not (rules).
*   Review the configuration of RBAC policies to ensure service accounts have the minimum necessary permissions, as mentioned in the investigation guide (note).
*   Implement enhanced monitoring and alerting for similar unauthorized access attempts to improve detection and response times for future incidents, improving overall cluster security (note).
