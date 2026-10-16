---
title: SQL Injection Vulnerability in Frappe HRMS
slug: 2026-10-frappe-hrms-sql-injection
description: Authenticated attackers can exploit a SQL injection vulnerability in specific Frappe HRMS API endpoints to extract sensitive database information due to missing input validation.
date: "2026-10-16T04:23:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:frappe:hrms:*:*:*:*:*:*:*:*
tags:
  - web-application-security
  - sql-injection
  - cve-2026-111389
vendors:
  - Frappe
products:
  - HRMS (< 14.38.2, < 15.64.0, < 16.18.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Frappe HRMS... contains a SQL injection vulnerability in some endpoints caused by missing input validation.
    confidence_band: high
cves:
  - id: CVE-2026-111389
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111389
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Frappe HRMS to versions 14.38.2, 15.64.0, or 16.18.0
      owner: IT Operations
      due: 48h
      evidence: Source document identifies these as the versions containing the fix.
  hunt_leads:
    - lead: Search web logs for SQL injection patterns originating from authenticated sessions
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: SQL injection vulnerability in API endpoints allows data extraction.
  mitigation_plan:
    - priority: immediate
      action: Patch HRMS to 14.38.2 or later
      owner: IT Operations
      addresses: CVE-2026-111389
      evidence: NVD vulnerability disclosure
---

Frappe HRMS versions 14.x before 14.38.2, 15.x before 15.64.0, and 16.x before 16.18.0 contain a critical SQL injection vulnerability originating from inadequate input validation on specific API endpoints. The flaw permits an authenticated user, regardless of their privilege level, to submit maliciously crafted HTTP requests that manipulate backend database queries. If exploited, this allows unauthorized access to data stored within the HRMS database. Given the nature of HRMS platforms, the data at risk typically includes personally identifiable information (PII), payroll details, and other sensitive corporate records. Organizations utilizing affected versions of Frappe HRMS should prioritize patching, as this vulnerability provides a direct pathway for data exfiltration once initial authentication is achieved.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to extract data from the backend database. This impacts any organization running the affected HRMS versions, exposing internal records to potentially any authenticated user within the system. The scale of impact corresponds to the volume and sensitivity of the data housed in the HRMS instance, with potential for significant compliance and privacy ramifications.

## Recommendation

- Upgrade Frappe HRMS to the patched versions immediately: 14.38.2, 15.64.0, 16.18.0 or later.
- Review web server access logs for anomalous SQL syntax (e.g., 'UNION SELECT', 'OR 1=1', '--') appearing in URI parameters or POST body data originating from authenticated sessions.
- Enforce the principle of least privilege by restricting user access to API endpoints to only those necessary for their specific roles to limit potential impact if an account is compromised.
