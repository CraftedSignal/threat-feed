---
title: Critical Vulnerabilities in NextGen Healthcare Mirth Connect
slug: 2026-09-mirth-connect-vulns
description: NextGen Healthcare Mirth Connect versions 4.7.1 and earlier contain three critical vulnerabilities including SQL injection and XML External Entity (XXE) injection flaws that allow for unauthorized data access and denial-of-service.
date: "2026-09-10T16:07:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - medical-devices
  - vulnerability
  - cisa
  - ics
vendors:
  - NextGen Healthcare
products:
  - Mirth Connect (<=v4.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerabilities allow unauthenticated XXE injection, providing a vector for external exploitation of public-facing interfaces.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-253-01
  - https://www.cve.org/CVERecord?id=CVE-2026-82583
  - https://www.cve.org/CVERecord?id=CVE-2026-78224
  - https://www.cve.org/CVERecord?id=CVE-2026-82578
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all Mirth Connect instances to version 4.7.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Vendor fix recommendation in CISA ICSMA-26-253-01.
  mitigation_plan:
    - priority: immediate
      action: Isolate Mirth Connect instances from internet access via firewall rules.
      owner: Network Security
      addresses: CVE-2026-78224, CVE-2026-82578
      evidence: Recommended practices section of CISA advisory.
---

NextGen Healthcare Mirth Connect versions 4.7.1 and earlier are affected by multiple high-severity vulnerabilities. These flaws include CVE-2026-82583, a SQL injection vulnerability within the Database Connector API that allows authenticated users to execute arbitrary SQL commands, potentially leading to credential disclosure, arbitrary file writes, and denial-of-service. Additionally, CVE-2026-78224 and CVE-2026-82578 involve improper restriction of XML External Entity (XXE) references within the XSLT Transformer step and XML batch processing, respectively. These XXE vulnerabilities enable unauthenticated attackers to perform data exfiltration and cause denial-of-service conditions. Mirth Connect is widely used in the healthcare sector for clinical data integration, making these flaws a significant target for actors seeking unauthorized access to sensitive medical data.

## Impact

Successful exploitation of these vulnerabilities can result in severe consequences, including the compromise of stored credentials for integrated systems, unauthorized access to sensitive patient data, arbitrary file system manipulation, and persistent denial-of-service of the Mirth Connect interface. These vulnerabilities affect healthcare organizations worldwide, potentially disrupting critical clinical workflows.

## Recommendation

* Immediately upgrade NextGen Healthcare Mirth Connect to version 4.7.2 or later as recommended by the vendor.
* Minimize network exposure by ensuring Mirth Connect instances are not directly accessible from the internet and are located behind firewalls.
* Implement defense-in-depth strategies to isolate clinical systems from general business networks.
* Monitor web server logs and database access logs for anomalous SQL queries or attempts to inject external entities into XML processing streams.
