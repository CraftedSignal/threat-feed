---
title: 'Osclass: SQL Injection in Item Model Handler (CVE-2026-113381)'
slug: 2026-10-osclass-sql-injection
description: Osclass versions up to 8.3.1 are vulnerable to a remote SQL injection attack due to insufficient sanitization of the sPattern argument in the Item::findUserItems function.
date: "2026-10-20T10:32:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:osclass:osclass:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - cve-2026-113381
vendors:
  - Osclass
products:
  - Osclass (<= 8.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-113381
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113381
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify and isolate public-facing Osclass instances
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-113381
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to block malicious SQL patterns in the sPattern parameter
      owner: IT Operations
      addresses: CVE-2026-113381
      evidence: Vulnerability in Item::findUserItems function
---

Osclass versions up to 8.3.1 contain a critical SQL injection vulnerability in the Item::findUserItems function, located within the file 'oc-includes/osclass/model/Item.php'. The vulnerability arises from improper sanitization of the 'sPattern' argument passed to the Item Model Handler. A remote attacker can exploit this flaw by submitting crafted input to the affected parameter, potentially allowing unauthorized access to the database or sensitive information disclosure. Public exploit code for this vulnerability is currently available, posing an immediate risk to installations that have not implemented compensating controls. Despite early disclosure attempts, the vendor has not responded or provided a patch, leaving legacy versions susceptible to exploitation.

## Impact

Successful exploitation of this SQL injection vulnerability allows remote attackers to manipulate backend database queries, which could lead to unauthorized data extraction, database modification, or complete compromise of the underlying database application. Organizations running Osclass versions 8.3.1 or older are at risk of data breach and loss of service integrity.

## Recommendation

* Identify all public-facing instances of Osclass version 8.3.1 or older and restrict access to the web interface via a Web Application Firewall (WAF) until the vulnerability is addressed by the vendor or internal patches are applied.
* Implement strict input validation on the application layer for the 'sPattern' parameter to ensure it does not contain malicious SQL metacharacters.
* Monitor database query logs for unusual syntax patterns, such as UNION statements or comment indicators, originating from web traffic to the application.
