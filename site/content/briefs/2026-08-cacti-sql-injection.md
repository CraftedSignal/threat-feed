---
title: SQL Injection Vulnerability in Cacti
slug: 2026-08-cacti-sql-injection
description: A vulnerability in Cacti versions prior to 1.2.27 allows an authenticated remote attacker to perform SQL injection, potentially leading to unauthorized database access or information disclosure.
date: "2026-08-06T15:20:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cacti:cacti:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*
vendors:
  - Cacti
products:
  - Cacti (< 1.2.27)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein entfernter, authentisierter Angreifer kann eine Schwachstelle in Cacti ausnutzen, um einen SQL-Injection Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2024-25641
    cvss: 9.1
    epss: 0.86303
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2684
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Cacti to version 1.2.27 or higher
      owner: IT Operations
      due: 48h
      evidence: CVE-2024-25641
  hunt_leads:
    - lead: Authenticated user requests containing SQL injection payloads
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: SQL injection vulnerability in Cacti
  mitigation_plan:
    - priority: immediate
      action: Upgrade Cacti
      owner: IT Operations
      addresses: CVE-2024-25641
      evidence: BSI Security Advisory
---

The BSI has reported a critical vulnerability in Cacti, a popular network monitoring and graphing tool. The flaw allows a remote, authenticated attacker to execute arbitrary SQL commands through improper input validation within the application. This vulnerability is tracked as CVE-2024-25641. Affected versions include all releases prior to 1.2.27. By successfully injecting malicious SQL queries, an attacker could manipulate database contents, bypass authentication mechanisms, or extract sensitive monitoring data stored within the backend database. This impact is significant for organizations relying on Cacti for network visibility, as it exposes the monitoring infrastructure to administrative compromise.

## Impact

Successful exploitation of this vulnerability enables an attacker to gain unauthorized access to the Cacti database. Given that Cacti often holds credentials for network devices and sensitive configuration data for managed infrastructure, a breach could lead to lateral movement or the compromise of the wider monitored network environment.

## Recommendation

* Immediately upgrade all Cacti installations to version 1.2.27 or later to patch CVE-2024-25641.
* Audit web server logs for suspicious SQL syntax in requests originating from authenticated users.
* Enforce strict access control for the Cacti administrative interface to minimize the risk of malicious authenticated users.
