---
brief_id: brief-2026-10-26-anuko-sqli
event_id: brief-2026-10-26-anuko-sqli
revision: 1
activity_at: "2026-10-26T21:06:13Z"
title: 'Anuko Time Tracker: Authenticated SQL Injection via puncher.php (CVE-2022-24707)'
slug: 2026-10-anuko-sqli
description: An authenticated SQL injection vulnerability in the Anuko Time Tracker puncher component allows attackers to exfiltrate database credentials via the date parameter.
date: "2026-10-26T21:06:13Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs internal lab validation
cpes:
  - cpe:2.3:a:anuko:time_tracker:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sqli
  - credential-theft
vendors:
  - Anuko
products:
  - Time Tracker (< 1.20.0.5642)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: 'CVE-2022-24707 (Anuko <= 1.20.0.5640): authenticated SQLi in puncher.php date parameter writes tt_users credentials into the entry note field.'
    confidence_band: high
cves:
  - id: CVE-2022-24707
    cvss: 7.4
    epss: 0.07159
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-24707
  - https://sploitus.com/exploit?id=KS:EXPLOITS-MULTI-HTTP-ANUKO_CVE_2022_24707_SQLI
  - https://sploitus.com/exploit?id=KS:EXPLOITS-MULTI-HTTP-ANUKO_CVE_2022_24707_SQLI&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2022-24707 Exploitation - SQL Injection in puncher.php
    description: Detects attempts to exploit CVE-2022-24707 by identifying suspicious SQL keywords injected into the date parameter of puncher.php
    platform: sigma
    severity: high
    tactics:
      - credential-access
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Anuko Time Tracker to 1.20.0.5642
      owner: IT Operations
      due: 48h
      evidence: Vulnerability mitigated in versions >= 1.20.0.5642
  hunt_leads:
    - lead: Identify successful exfiltration of tt_users credentials
      technique_id: T1505
      data_needed:
        - Web access logs for /puncher.php
        - Application database audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The exploit writes tt_users credentials into the entry note field.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.20.0.5642
      owner: IT Operations
      addresses: CVE-2022-24707
      evidence: Vendor patch availability
---

CVE-2022-24707 is an authenticated SQL injection vulnerability affecting Anuko Time Tracker versions prior to 1.20.0.5642. The vulnerability resides in the puncher.php component, where the 'date' parameter in a POST request fails to properly sanitize input. An attacker with low-level privileges can inject arbitrary SQL commands to extract contents from the 'tt_users' table by leveraging the application's functionality to write entry notes.

## Attack Chain
1. Attacker authenticates to the target Anuko Time Tracker instance using valid user credentials.
2. Attacker interacts with the /puncher.php interface to initiate a time entry session.
3. Attacker identifies the project ID associated with the current user session.
4. Attacker sends a malicious POST request to /puncher.php, injecting a SQL payload into the 'date' parameter designed to query the 'tt_users' table.
5. The application executes the injected SQL, causing the database to write the contents of the 'tt_users' table into the 'note' field of the current time entry.
6. Attacker navigates to /time_edit.php to view the created entry and exfiltrate the stolen credentials from the note field.

## Impact
Successful exploitation allows for the exfiltration of usernames and password hashes from the 'tt_users' table, leading to potential privilege escalation or full compromise of the application.

## Recommendation
- Upgrade Anuko Time Tracker to version 1.20.0.5642 or later to patch the vulnerable parameter handling in puncher.php.
- Audit existing time entries for suspicious content in the 'note' field, particularly those containing database syntax or account credentials.
- Implement restrictive access controls for the 'puncher' plugin if it is not required for all users.
