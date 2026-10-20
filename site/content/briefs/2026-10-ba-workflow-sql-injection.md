---
title: SQL Injection Vulnerability in BA-Workflow
slug: 2026-10-ba-workflow-sql-injection
description: An authenticated SQL injection vulnerability in YS-infoware BA-Workflow allows remote attackers to execute arbitrary database commands, compromising data integrity and confidentiality.
date: "2026-10-20T08:34:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ys-infoware:ba-workflow:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
vendors:
  - YS-infoware
products:
  - BA-Workflow
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated remote attackers can inject arbitrary SQL statements to read, modify, and delete database contents.
    confidence_band: high
cves:
  - id: CVE-2026-113405
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113405
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch BA-Workflow to the vendor-recommended version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-113405
  hunt_leads:
    - lead: Identify authenticated web sessions querying the database with unusual SQL keywords
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: SQL injection vulnerability allows arbitrary query execution
  mitigation_plan:
    - priority: immediate
      action: Apply security patches provided by YS-infoware
      owner: IT Operations
      addresses: CVE-2026-113405
      evidence: Vulnerability remediation
---

YS-infoware BA-Workflow contains a SQL injection vulnerability identified as CVE-2026-113405. The flaw exists within the application's input processing logic and is reachable by authenticated remote attackers. By injecting malicious SQL payloads into vulnerable parameters, an attacker can bypass authorization controls to read, modify, or delete sensitive data stored within the backend database. Given the nature of SQL injection, this vulnerability poses a significant risk to the integrity and confidentiality of the entire database managed by the workflow system. Organizations utilizing BA-Workflow should prioritize patching or restricting access to the application until a security update is applied, as the capability for an attacker to manipulate core business data presents a critical operational risk.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to gain unauthorized access to the application's backend database. Depending on the database permissions assigned to the service account used by BA-Workflow, an attacker could extract entire databases, modify administrative records, or destroy data, potentially leading to a total loss of data integrity and disclosure of sensitive information.

## Recommendation

* Prioritize upgrading BA-Workflow to the latest vendor-supplied patch addressing CVE-2026-113405.
* Monitor application logs for unusual database query patterns or common SQL injection syntax (e.g., 'UNION SELECT', 'OR 1=1', '--') targeting the BA-Workflow web interface.
* Implement stricter database permissions for the service account running the BA-Workflow application to limit the potential scope of damage during an exploitation attempt.
