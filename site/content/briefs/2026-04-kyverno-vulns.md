---
title: Multiple Vulnerabilities in Kyverno Allow Privilege Escalation and Data Manipulation
slug: 2026-04-kyverno-vulns
description: An authenticated remote attacker can exploit multiple vulnerabilities in Kyverno to disclose information, bypass security measures, manipulate data, and gain elevated privileges.
date: "2026-04-16T11:19:02Z"
severities:
  - critical
tags:
  - kyverno
  - kubernetes
  - privilege-escalation
  - data-manipulation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Availability Management
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1152
rules:
  - title: Detect Kyverno Policy Bypass Attempts via API Server
    description: Detects attempts to bypass Kyverno policies by monitoring API server requests that violate existing policies.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Kyverno Policy Modification
    description: Detects unauthorized modification of Kyverno policies by monitoring Kubernetes audit logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
  - title: Detect Kubernetes Resource Creation by Kyverno with Elevated Privileges
    description: Detects suspicious Kubernetes resource creation events initiated by Kyverno with elevated privileges.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Kyverno, a Kubernetes policy engine, is susceptible to multiple vulnerabilities that can be exploited by authenticated remote attackers. These flaws allow attackers to disclose sensitive information, circumvent security measures, manipulate data, and ultimately gain elevated privileges within the Kubernetes environment. Successful exploitation of these vulnerabilities could lead to unauthorized access to sensitive resources, disruption of services, and potential compromise of the entire…
