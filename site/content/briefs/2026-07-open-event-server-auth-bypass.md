---
title: Open Event Server Authentication Bypass for Member Roster Export (CVE-2026-63101)
slug: 2026-07-open-event-server-auth-bypass
description: An authentication bypass vulnerability, CVE-2026-63101, in Open Event Server through version 1.19.1 allows unauthenticated attackers to export the complete member roster of any group by exploiting unauthenticated CSV export and task status endpoints, leading to the exfiltration of sensitive data like email addresses, names, and roles.
date: "2026-07-17T17:23:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - data-exfiltration
  - web-application
  - cve
vendors:
  - Open Event
products:
  - Open Event Server <= 1.19.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Open Event Server through 1.19.1 contains a missing authentication vulnerability that allows unauthenticated attackers to export the complete member roster of any group...
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Attackers can enumerate sequential group IDs via brute-force...
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: '...to export the complete member roster of any group, including email addresses, names, join dates, and roles...'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: '...to retrieve a download URL containing the full member CSV.'
    confidence_band: high
cves:
  - id: CVE-2026-63101
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63101
rules:
  - title: Detect CVE-2026-63101 Exploitation - Unauthenticated Group Roster Export Request
    description: Detects CVE-2026-63101 exploitation - unauthenticated HTTP POST requests to the group followers CSV export endpoint in Open Event Server, indicating an attempt to trigger sensitive data export.
    platform: sigma
    severity: high
    tactics:
      - collection
      - exfiltration
    techniques:
      - T1041
      - T1213
    data_sources:
      - webserver
  - title: Detect CVE-2026-63101 Exploitation - Unauthenticated Export Task Status Polling
    description: Detects CVE-2026-63101 exploitation - unauthenticated HTTP GET requests to the export task status endpoint in Open Event Server, indicating an attacker polling for sensitive data export completion.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - exfiltration
    techniques:
      - T1041
      - T1595.001
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-63101 affects Open Event Server up to and including version 1.19.1, presenting a critical missing authentication vulnerability. This flaw enables unauthenticated attackers to bypass security controls and export the complete member roster of any group. The attack leverages specific API endpoints that lack proper authentication decorators, allowing unauthorized access to sensitive user data such as email addresses, names, join dates, and roles. Attackers can programmatically discover group IDs, trigger the export process, and retrieve the resulting CSV file containing the full member details. This vulnerability poses a significant risk of data exfiltration and privacy breaches for organizations utilizing affected versions of Open Event Server.

## Attack Chain

1. Attacker identifies an instance of Open Event Server.
2. Attacker enumerates sequential group IDs, potentially by brute-forcing numerical IDs for target organizations.
3. Attacker crafts and sends an unauthenticated HTTP POST request to the `/api/groups/{groupID}/followers/export_csv` endpoint, specifying a known or enumerated `groupID`.
4. The vulnerable Open Event Server processes the unauthenticated request, initiating a CSV export task for the specified group's member roster.
5. Attacker polls an unauthenticated task status endpoint (e.g., `/api/export_tasks/{taskID}/status`) using the `taskID` received from the previous export request, to monitor the completion status of the export job.
6. Once the export task is completed, the task status response provides a download URL for the generated CSV file.
7. Attacker accesses the provided download URL to retrieve the CSV file, which contains the complete member roster including email addresses, names, join dates, and roles.

## Impact

Successful exploitation of CVE-2026-63101 leads to the complete compromise and exfiltration of sensitive member data from affected Open Event Server instances. This includes personally identifiable information (PII) such as email addresses, full names, account creation dates, and assigned roles within groups. The exposure of this data can result in severe privacy violations, facilitate targeted phishing campaigns, social engineering attacks against organization members, and compliance failures under data protection regulations. The ease of exploitation, requiring no authentication, means a wide range of organizations using Open Event Server could be at risk of significant data breaches.

## Recommendation

* Patch CVE-2026-63101 immediately by upgrading Open Event Server to a version beyond 1.19.1 that addresses this vulnerability.
* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious activity related to CVE-2026-63101.
* Monitor web server logs for HTTP POST requests to `/api/groups/*/followers/export_csv` and HTTP GET requests to `/api/export_tasks/*/status` without associated authentication tokens or session IDs.
