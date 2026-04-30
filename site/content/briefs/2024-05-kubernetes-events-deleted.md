---
title: Kubernetes Event Deletion for Defense Evasion
slug: 2024-05-kubernetes-events-deleted
description: An adversary may delete Kubernetes events to evade detection and hide malicious activity within a Kubernetes environment by removing audit logs.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - defense-evasion
  - kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Delete%20K8S%20events/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/application/kubernetes/audit/kubernetes_audit_events_deleted.yml
rules:
  - title: Kubernetes Events Deleted
    description: Detects when events are deleted in Kubernetes clusters via audit logs.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1070
    data_sources:
      - application
      - kubernetes
      - audit
  - title: Kubernetes Role Deletion
    description: Detects deletion of Kubernetes roles, which could indicate an attempt to remove audit or access controls.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1070
    data_sources:
      - application
      - kubernetes
      - audit
rules_count: 2
---

Attackers targeting Kubernetes environments may attempt to delete Kubernetes events as a means of covering their tracks. This technique, often employed after successful exploitation or lateral movement, aims to eliminate audit logs and other traces of malicious activity. By removing these logs, attackers can significantly hinder incident response efforts and prolong the duration of their access. While the specifics of initial access will vary, this action will typically be performed using kubectl or similar tools with sufficient privileges within the Kubernetes cluster. Defenders need to monitor for unexpected deletion of event logs to identify potentially compromised systems.

## Attack Chain

1.  Initial compromise of a container or node within the Kubernetes cluster using an exploit (e.g., exploiting a vulnerability in a containerized application).
2.  Establish persistence by creating a malicious pod or modifying existing deployments to include backdoors.
3.  Escalate privileges within the cluster, potentially by exploiting misconfigured RBAC policies or vulnerable service accounts.
4.  Identify Kubernetes event logs that contain evidence of the attacker's activities, such as pod deployments, privilege escalation attempts, or network connections.
5.  Use `kubectl delete events` command with appropriate privileges to remove targeted event logs from the Kubernetes audit logs.
6.  Verify that the targeted event logs have been successfully removed from the cluster's audit trail.
7.  Continue lateral movement and data exfiltration, now with reduced risk of detection due to the deleted event logs.

## Impact

Successful deletion of Kubernetes events allows attackers to operate within the cluster undetected for extended periods. This can lead to significant data breaches, system compromise, and disruption of services. The absence of event logs makes forensic investigation and incident response extremely challenging, potentially leading to inaccurate assessments of the scope and impact of the attack. While the exact number of victims is unknown, this technique, if successful, significantly amplifies the damage caused by any initial intrusion.

## Recommendation

*   Deploy the Sigma rule "Kubernetes Events Deleted" to your SIEM to detect event deletion attempts in your Kubernetes environment (logsource: application, product: kubernetes, service: audit).
*   Review and harden RBAC policies to minimize the risk of unauthorized event deletion.
*   Implement strong audit logging practices and ensure that audit logs are securely stored and protected from tampering.
