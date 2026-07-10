---
title: Kubernetes Cron Job Creation Detected via Audit Logs
slug: 2024-01-03-kubernetes-cronjob-creation
description: The creation of Kubernetes cron jobs is detected by monitoring Kubernetes Audit logs, a technique that could enable attackers to execute scheduled malicious tasks, potentially leading to persistent attacks, service disruptions, or unauthorized access to sensitive information.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - cronjob
  - scheduling
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
rules:
  - title: Kubernetes Cron Job Creation Detected
    description: Detects the creation of Kubernetes cron jobs by monitoring Kubernetes Audit logs for cron job creation events.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.007
    data_sources:
      - webserver
      - linux
  - title: Kubernetes Cron Job Creation by non-admin User
    description: Detects cron job creation by non-admin users
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.007
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This analytic focuses on detecting the creation of Kubernetes cron jobs by monitoring Kubernetes Audit logs for cron job creation events. Kubernetes cron jobs are designed to schedule tasks for automatic execution at specified intervals. Attackers can abuse this functionality to execute malicious tasks repeatedly and automatically, posing a significant threat to the Kubernetes infrastructure. Detecting such activity is crucial for Security Operations Centers (SOCs) to prevent persistent attacks, service disruptions, and unauthorized access to sensitive information. The detection logic analyzes Kubernetes Audit logs for "create" events associated with cron job resources.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to the Kubernetes cluster, potentially by exploiting a vulnerability or using compromised credentials.
2.  **Privilege Escalation:** The attacker may attempt to escalate privileges within the cluster to gain the necessary permissions to create cron jobs.
3.  **Cron Job Creation:** The attacker creates a new cron job by sending a "create" request to the Kubernetes API server targeting the "cronjobs" resource. This is the event detected by this analytic.
4.  **Scheduled Task Execution:** The cron job is configured to execute a specific task at a defined schedule, such as running a malicious script or deploying a rogue container.
5.  **Lateral Movement:** The scheduled task may facilitate lateral movement within the cluster by accessing other pods or services.
6.  **Data Exfiltration/Disruption:** The attacker uses the compromised resources to exfiltrate sensitive data or disrupt services.
7.  **Persistence:** The cron job ensures that the malicious task is executed repeatedly, providing a persistent foothold within the Kubernetes environment.

## Impact

Successful exploitation via malicious cron job creation can lead to a range of damaging outcomes. These include persistent attacks, service disruptions due to resource exhaustion or malicious code execution, and unauthorized access to sensitive information stored within the Kubernetes cluster. The impact can range from data breaches and intellectual property theft to complete system compromise and denial of service.

## Recommendation

*   Enable Kubernetes audit logging to capture API server requests. This is essential for the `kube_audit` data source used by this detection (https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/).
*   Deploy the provided Sigma rule to your SIEM to detect suspicious cron job creation events based on the user (`user`) and source IP address (`src_ip`).
*   Investigate any detected cron job creation events, especially those originating from unusual users or source IP addresses. Consider leveraging the drilldown searches to further investigate detected events.
*   Implement role-based access control (RBAC) policies to restrict the ability to create cron jobs to authorized users and service accounts only.
*   Monitor the images used in newly created cron jobs, and compare them to known images within the cluster.
