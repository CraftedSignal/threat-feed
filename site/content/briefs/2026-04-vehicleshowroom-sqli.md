---
title: SQL Injection Vulnerability in Vehicle Showroom Management System 1.0 (CVE-2026-6036)
slug: 2026-04-vehicleshowroom-sqli
description: A remote SQL injection vulnerability (CVE-2026-6036) exists in the Vehicle Showroom Management System 1.0 due to improper sanitization of the VEHICLE_ID parameter in /util/VehicleDetailsFunction.php, potentially allowing attackers to execute arbitrary SQL commands.
date: "2026-04-10T09:16:51Z"
severities:
  - high
tags:
  - sqli
  - cve-2026-6036
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server-Side Website Compromise
cves:
  - id: CVE-2026-6036
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6036
  - https://code-projects.org/
  - https://github.com/TAnNbR/CVE/issues/3
  - https://vuldb.com/vuln/356617
rules:
  - title: Detect Suspicious SQL Injection Attempts in Vehicle Showroom Management System
    description: Detects potential SQL injection attempts targeting the Vehicle Showroom Management System by monitoring for suspicious characters and SQL keywords in the VEHICLE_ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
      - T1505.001
    data_sources:
      - webserver
      - linux
  - title: Detect Direct Access to VehicleDetailsFunction.php
    description: Detects direct access to the VehicleDetailsFunction.php file, which might indicate an attempt to exploit a known vulnerability or bypass intended access controls.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6036 is a SQL injection vulnerability affecting Vehicle Showroom Management System version 1.0. The vulnerability resides within the `/util/VehicleDetailsFunction.php` file, specifically involving the `VEHICLE_ID` parameter. An unauthenticated attacker can remotely exploit this vulnerability by injecting malicious SQL code into the `VEHICLE_ID` argument. This allows for the potential execution of arbitrary SQL commands on the underlying database, potentially leading to data breaches…
