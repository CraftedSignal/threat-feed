---
title: SQL Injection Vulnerability in Online-Appointment-Booking-System
slug: 2026-10-online-appointment-sql-injection
description: An unauthenticated SQL injection vulnerability in the Online-Appointment-Booking-System Admin CRUD endpoint allows remote attackers to execute arbitrary SQL commands via the cid or did parameters.
date: "2026-10-13T16:36:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:girishsaraf:online_appointment_booking_system:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - web-vulnerability
  - cve
vendors:
  - girishsaraf
products:
  - Online-Appointment-Booking-System (up to commit f427b4757128ca253d33d0cc4e87bbb9c999a4d5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument cid/did leads to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-109522
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109522
rules:
  - title: Detect CVE-2026-109522 - SQL Injection in deleteclinic.php
    description: Detects exploitation attempts against CVE-2026-109522 by monitoring requests to the vulnerable deleteclinic.php endpoint containing SQL injection metacharacters in query parameters.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rules to block malicious query parameters on /Admin/deleteclinic.php
      owner: SOC
      due: 24h
      evidence: Public exploit available for CVE-2026-109522
  mitigation_plan:
    - priority: immediate
      action: Remove or restrict access to the Admin/deleteclinic.php file if not critical for operations
      owner: IT Operations
      addresses: CVE-2026-109522
      evidence: Source documentation of file-specific vulnerability
---

The Online-Appointment-Booking-System, developed by girishsaraf, contains a critical SQL injection vulnerability tracked as CVE-2026-109522. The vulnerability resides in the Admin/deleteclinic.php file within the Admin CRUD component. By manipulating the 'cid' or 'did' arguments in HTTP requests, a remote, unauthenticated attacker can inject arbitrary SQL commands into the backend database. This issue affects all versions of the application up to commit f427b4757128ca253d33d0cc4e87bbb9c999a4d5. As the project follows a continuous delivery model without specific versioning, users are advised to review the source code for the presence of the vulnerable Admin/deleteclinic.php file. Public exploit code for this vulnerability has been disclosed, increasing the risk of exploitation by opportunistic threat actors.

## Impact

Successful exploitation of CVE-2026-109522 allows an unauthenticated remote attacker to gain unauthorized access to the application database. This could result in complete data exfiltration of appointment records, clinic data, and potential administrative account compromise. Given the public availability of exploit code, organizations deploying this system are at high risk of immediate compromise if they remain on vulnerable builds.

## Recommendation

Prioritized actions for security teams:
- Identify and audit any deployments of the Online-Appointment-Booking-System in your environment.
- Apply security controls at the Web Application Firewall (WAF) layer to inspect and block HTTP requests to Admin/deleteclinic.php containing suspicious SQL syntax in the 'cid' or 'did' parameters.
- Monitor web server access logs for anomalous requests to the deleteclinic.php endpoint, particularly those containing common SQL injection payloads.
- Evaluate the necessity of the Online-Appointment-Booking-System in your infrastructure until a patch is provided by the maintainer.
