---
title: GCP Firewall Rule Deletion for Defense Evasion
slug: 2024-01-gcp-firewall-deletion
description: The deletion of firewall rules in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine is detected, potentially weakening security controls and enabling unauthorized access or data exfiltration by adversaries.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - defense-evasion
  - gcp
vendors:
  - Google
products:
  - Google Cloud Platform
  - Google Cloud VPC
  - Google App Engine
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://cloud.google.com/vpc/docs/firewalls
  - https://cloud.google.com/appengine/docs/standard/python/understanding-firewalls
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/007/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: GCP Firewall Rule Deletion
    description: Detects when a firewall rule is deleted in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.007
    data_sources:
      - cloudtrail
      - gcp
  - title: GCP Compute Firewall Deletion via gcloud
    description: Detects firewall deletion events initiated via gcloud command-line tool
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.007
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection identifies when a firewall rule is deleted in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine. Firewall rules are critical for controlling network traffic to and from virtual machine (VM) instances or specific applications. An adversary may delete a firewall rule to weaken a target's security controls, facilitating unauthorized access or data exfiltration. This behavior can be indicative of a defense evasion attempt. The deletion events are captured in audit logs within GCP, which are then monitored for specific actions related to firewall rule deletion in either VPC or App Engine environments.

## Attack Chain

1.  An attacker gains initial access to a GCP account, potentially through compromised credentials or exploiting a vulnerability.
2.  The attacker enumerates existing firewall rules within the VPC or App Engine environment to identify potential targets for deletion.
3.  Using compromised credentials or a service account, the attacker initiates the deletion of a specific firewall rule. The `gcloud` CLI or GCP console could be used.
4.  The firewall rule is removed, altering the network access control configuration.
5.  The attacker leverages the modified firewall configuration to establish unauthorized connections to internal resources.
6.  The attacker moves laterally within the GCP environment, accessing sensitive data or systems previously protected by the deleted firewall rule.
7.  The attacker exfiltrates data or performs other malicious activities, taking advantage of the weakened security posture.

## Impact

Successful deletion of GCP firewall rules can lead to significant security breaches, including unauthorized access to sensitive data, lateral movement within the cloud environment, and potential data exfiltration. The impact is highly dependent on the scope and purpose of the deleted firewall rule. This activity allows attackers to bypass intended security controls.

## Recommendation

*   Deploy the Sigma rule `GCP Firewall Rule Deletion` to your SIEM to detect unauthorized firewall deletions based on `data_stream.dataset:gcp.audit and event.action:(*.compute.firewalls.delete or google.appengine.*.Firewall.Delete*Rule)`.
*   Enable GCP audit logging to ensure that all firewall rule deletion events are captured for analysis.
*   Review and update access controls and permissions for users and service accounts to minimize the risk of unauthorized firewall rule modifications.
*   Implement enhanced monitoring and alerting for firewall rule changes to detect and respond to similar threats more quickly in the future, based on `event.action` logs.
