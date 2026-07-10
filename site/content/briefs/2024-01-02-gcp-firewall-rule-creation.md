---
title: GCP Firewall Rule Creation for Defense Evasion
slug: 2024-01-02-gcp-firewall-rule-creation
description: An adversary may create a new firewall rule in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine to weaken their target's security controls and allow more permissive ingress or egress traffic flows for their benefit, indicating a defense evasion attempt.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - gcp
  - firewall
  - defense_evasion
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
rules:
  - title: GCP Firewall Rule Creation
    description: Detects the creation of new firewall rules in Google Cloud Platform (GCP), which can be indicative of defense evasion.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - gcp
      - gcp.audit
  - title: GCP Firewall Rule Created by Unusual Identity
    description: Detects GCP firewall rule creation events by principals that are not typically associated with administrative tasks.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - gcp
      - gcp.audit
rules_count: 2
---

This detection identifies the creation of firewall rules within Google Cloud Platform (GCP), specifically targeting Virtual Private Cloud (VPC) and App Engine environments. While firewall rules are legitimate components of network security, adversaries can exploit them to weaken existing defenses. By creating overly permissive rules, attackers can bypass security controls and establish unauthorized ingress or egress traffic flows. The focus is on detecting unexpected or suspicious firewall rule creation events that could indicate malicious activity. The original Elastic detection rule `30562697-9859-4ae0-a8c5-dab45d664170` published in 2020 and updated in 2026, helps security teams audit configuration changes and identify potential defense evasion attempts within their GCP environments. The scope includes both VPC and App Engine firewall configurations.

## Attack Chain

1.  The attacker gains initial access to a GCP account, potentially through compromised credentials or exploiting a misconfigured service account.
2.  The attacker enumerates existing firewall rules and network configurations to identify potential weaknesses.
3.  The attacker crafts a new firewall rule designed to allow unauthorized traffic, such as opening specific ports or IP ranges.
4.  The attacker uses the `gcloud` command-line tool or the GCP console to create the new firewall rule, targeting either VPC or App Engine.
5.  The newly created firewall rule is activated, effectively modifying the network's security posture.
6.  The attacker leverages the permissive firewall rule to establish a command and control (C2) channel or exfiltrate sensitive data.
7.  The attacker uses the open port(s) to move laterally within the network.
8.  The attacker achieves their objective (data exfiltration, system compromise, etc.)

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, compromised systems, and potential data breaches. The low severity acknowledges that legitimate firewall rule changes occur regularly, but highlights the need to monitor and validate these changes to detect malicious activity. If successful, attackers can bypass existing security controls and potentially gain complete control of affected systems and applications.

## Recommendation

*   Deploy the Sigma rule `GCP Firewall Rule Creation` to your SIEM to detect suspicious firewall rule creations in your GCP environment. Tune the rule based on your organization's baseline activity and known service accounts.
*   Review the audit logs for `event.dataset:gcp.audit` entries, specifically focusing on the `event.action` fields: `*.compute.firewalls.insert` or `google.appengine.*.Firewall.Create*Rule` to validate the source of firewall rule changes.
*   Implement role-based access control (RBAC) to limit the ability to create or modify firewall rules to only authorized personnel, mitigating the risk of compromised accounts creating malicious rules.
*   Establish a baseline of expected firewall rules and configurations to quickly identify deviations that could indicate malicious activity, using the provided references about GCP firewalls.
