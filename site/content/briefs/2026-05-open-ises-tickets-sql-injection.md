---
title: Open ISES Tickets SQL Injection Vulnerability (CVE-2026-48235)
slug: 2026-05-open-ises-tickets-sql-injection
description: Open ISES Tickets versions before 3.44.2 are vulnerable to SQL injection (CVE-2026-48235) due to unsanitized GPS data, allowing attackers to manipulate responder data by compromising the GPS tracker endpoint.
date: "2026-05-21T18:19:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-48235
  - web-application
products:
  - Open ISES Tickets < 3.44.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-48235
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48235
rules:
  - title: Detect Suspicious GPS Data in Web Requests
    description: Detects CVE-2026-48235 exploitation - attempts to inject SQL commands via GPS data in web requests to Open ISES Tickets.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SQL Injection Characters in HTTP POST Requests
    description: Detects common SQL injection characters in HTTP POST requests, potentially indicating exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Open ISES Tickets versions before 3.44.2 are susceptible to a SQL injection vulnerability (CVE-2026-48235) stemming from the processing of GPS data. The vulnerability lies in `incs/remotes.inc.php`, where latitude, longitude, callsign, mph, altitude, and timestamp values extracted from external GPS tracking services (InstaMapper and Google Latitude) are directly concatenated into SQL queries. This lack of sanitization creates an opportunity for attackers who can compromise or impersonate the remote GPS tracker endpoint to inject arbitrary SQL commands, potentially leading to unauthorized data modification within the responder location, tracks, and assignment tables. Exploitation could enable malicious actors to manipulate responder deployments and track data.

## Attack Chain

1. The attacker identifies an Open ISES Tickets instance using InstaMapper or Google Latitude integration.
2. The attacker gains control over, or impersonates, the remote GPS tracker endpoint.
3. The attacker crafts malicious XML/JSON responses containing SQL injection payloads in the latitude, longitude, callsign, mph, altitude, or timestamp fields.
4. The Open ISES Tickets server parses the crafted XML/JSON response from the compromised GPS tracker.
5. The server concatenates the unsanitized data into UPDATE or INSERT SQL statements within `incs/remotes.inc.php`.
6. The injected SQL code is executed against the Open ISES Tickets database.
7. The attacker manipulates responder location, tracks, and assignment data within the database.
8. The attacker achieves their objective, such as diverting responders or falsifying tracking information.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-48235) could allow an attacker to manipulate responder deployments, tracks, and assignments. This could lead to incorrect responder dispatches, delayed response times, or complete disruption of the incident management system. The impact is significant, potentially affecting public safety and emergency response operations that rely on accurate location data.

## Recommendation

*   Upgrade Open ISES Tickets to version 3.44.2 or later to patch CVE-2026-48235.
*   Implement input validation and sanitization on all GPS data received from external sources to prevent SQL injection, focusing on the latitude, longitude, callsign, mph, altitude, and timestamp fields.
*   Deploy the Sigma rule `Detect Suspicious GPS Data in Web Requests` to identify potential SQL injection attempts.
*   Harden the GPS tracker endpoint by implementing strong authentication and authorization controls to prevent unauthorized access and impersonation.
