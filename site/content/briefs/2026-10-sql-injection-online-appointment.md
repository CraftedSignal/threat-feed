---
title: SQL Injection in Online-Appointment-Booking-System
slug: 2026-10-sql-injection-online-appointment
description: An unauthenticated SQL injection vulnerability in the Patient Login Handler allows remote attackers to execute arbitrary SQL commands via the uname or psw parameters.
date: "2026-10-05T20:48:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:girishsaraf:online_appointment_booking_system:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - girishsaraf
products:
  - Online-Appointment-Booking-System (<= f427b4757128ca253d33d0cc4e87bbb9c999a4d5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument uname/psw results in sql injection. It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-105387
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105387
rules:
  - title: Detect CVE-2026-105387 Exploitation - SQL Injection in cover.php
    description: Detects exploitation attempts against CVE-2026-105387 where SQL injection payloads are injected into the uname or psw parameters in cover.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all instances of the affected software and apply WAF filtering for CVE-2026-105387
      owner: IT Operations
      due: 48h
      evidence: Public exploit available for this vulnerability
  hunt_leads:
    - lead: Search logs for unauthorized queries to cover.php
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary SQL execution
  mitigation_plan:
    - priority: immediate
      action: Block public access to the vulnerable application component
      owner: IT Operations
      addresses: CVE-2026-105387
      evidence: SQL injection vulnerability in Patient Login Handler
---

A SQL injection vulnerability (CVE-2026-105387) has been identified in the Online-Appointment-Booking-System developed by girishsaraf. The vulnerability resides in the mysqli_query function within cover.php, specifically within the Patient Login Handler component. An unauthenticated remote attacker can exploit this flaw by sending specially crafted input to the uname or psw arguments. 

Because the application does not properly sanitize these inputs before passing them to the database query, an attacker can manipulate the underlying SQL command. This enables unauthorized data extraction, authentication bypass, or other database-level impacts. Public exploit code for this vulnerability is currently available, increasing the risk of exploitation. As the software utilizes a rolling release model, there is no specific version number to identify a patched release, and the maintainer has not yet provided a fix for the identified vulnerability.

## Impact

The successful exploitation of this vulnerability allows unauthenticated remote attackers to execute arbitrary SQL commands against the database. This can lead to full compromise of the application's user database, unauthorized access to sensitive patient appointment information, and potentially complete data exfiltration.

## Recommendation

Prioritized actions for security teams:
- Identify all instances of the girishsaraf Online-Appointment-Booking-System within the environment.
- Monitor web server access logs for anomalous characters (e.g., single quotes, comment indicators, or SQL syntax) in requests directed at cover.php.
- Restrict access to the application via network segmentation until a patch or mitigation is verified.
- Implement Web Application Firewall (WAF) rules to inspect and block inputs containing common SQL injection payloads targeted at the login parameters.
