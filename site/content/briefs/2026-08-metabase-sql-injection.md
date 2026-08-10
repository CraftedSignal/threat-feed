---
title: Critical SQL Injection and Privilege Escalation Vulnerability in Metabase
slug: 2026-08-metabase-sql-injection
description: An unauthenticated remote attacker can exploit a vulnerability in Metabase to perform SQL injection and escalate privileges.
date: "2026-08-10T13:25:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - privilege-escalation
  - web-application
vendors:
  - Metabase
products:
  - Metabase
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Metabase ausnutzen, um einen SQL-Injection Angriff durchzuführen
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Schwachstelle ermöglicht SQL-Injection und Privilegieneskalation
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2715
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Metabase to the latest available vendor version
      owner: IT Operations
      due: 24h
      evidence: Critical vulnerability reported by CERT-Bund
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to Metabase via firewall rules
      owner: IT Operations
      addresses: Public-facing application exploitation
      evidence: Exploit requires remote, unauthenticated access
---

Metabase contains a critical security vulnerability that allows an unauthenticated remote attacker to execute SQL injection attacks and achieve privilege escalation within the application. This flaw poses a significant risk to data confidentiality and integrity, as successful exploitation provides unauthorized access to database contents and administrative functions. Defenders should prioritize patching or restricting access to the Metabase instance until remediation is applied.

## Impact

Successful exploitation results in full database compromise and unauthorized administrative control over the Metabase instance. This facilitates the extraction of sensitive information, modification of data, and persistent access to backend systems connected via the reporting tool.

## Recommendation

- Immediately update Metabase instances to the latest version provided by the vendor.
- Restrict access to the Metabase interface to trusted networks only until patches are deployed.
- Review database audit logs for anomalous SQL queries originating from the Metabase service account.
