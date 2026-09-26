---
title: Unauthenticated Query Injection in Parse Server Device Token Deduplication
slug: 2026-09-parse-server-injection
description: A vulnerability in Parse Server's device token deduplication logic allows unauthenticated remote attackers to inject NoSQL query operators, leading to unauthorized deletion of device registrations.
date: "2026-09-26T15:03:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:parseplatform:parse-server:*:*:*:*:*:*:*:*
tags:
  - cve-2026-100631
  - injection
  - nosql-injection
  - denial-of-service
vendors:
  - Parse
products:
  - Parse Server (< 8.6.90, 9.0.0 <= v < 9.10.1-alpha.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker who knows only the public application ID can submit non-string values in these fields to inject query operators.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Deleted registrations cannot be recovered on the server, so push notifications cannot be delivered until every client re-registers.
    confidence_band: high
cves:
  - id: CVE-2026-100631
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100631
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Parse Server to version 8.6.90 or 9.10.1-alpha.9
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-100631 fixed in these versions
  mitigation_plan:
    - priority: immediate
      action: Upgrade to fixed version
      owner: IT Operations
      addresses: CVE-2026-100631
      evidence: Source explicitly states upgrade is the only available fix
---

Parse Server (versions prior to 8.6.90 and 9.0.0 through 9.10.1-alpha.8) is vulnerable to a NoSQL query injection attack within its device token deduplication mechanism. The vulnerability exists because the application fails to validate the data type of client-supplied installation fields before using them to construct database queries. An unauthenticated remote attacker possessing only the public application ID can provide non-string values (such as objects or arrays) within these fields, causing the deduplication cleanup process to execute malicious query logic. Because this cleanup process runs with elevated privileges before standard class-level permissions are validated, an attacker can delete all device registration records associated with an application or specific subsets defined by the injected criteria. This disruption effectively prevents the delivery of push notifications to affected users, and because the data is purged, recovery is only possible through client-side re-registration. No account access or master keys are required to trigger this impact, making it a critical availability risk for any deployment exposing the REST API.

## Attack Chain

1. The attacker identifies an internet-facing Parse Server deployment exposing the REST API.
2. The attacker uses the public application ID to target the specific instance.
3. The attacker constructs a malicious HTTP request targeting the installation deduplication endpoint.
4. The attacker provides non-string data (e.g., JSON objects containing query operators like '$ne' or '$in') within the device token installation fields.
5. The Parse Server backend receives the request and triggers the deduplication cleanup logic.
6. The database driver interprets the injected query operators due to improper type validation.
7. The system executes the modified query with elevated, administrative-level privileges, bypassing class-level permission checks.
8. The database performs an unauthorized delete operation, purging targeted device registration records and disabling push notifications.

## Impact

The successful exploitation of this vulnerability results in the permanent loss of device registration records for the affected Parse Server application. This leads to a total service outage for push notification functionality across the targeted installation. Because the records are deleted from the database without server-side backups available for restoration, legitimate users must manually re-register their devices to regain push notification services. This vulnerability affects all deployments that expose the REST API and utilize push notifications in their default configuration.

## Recommendation

1. Upgrade Parse Server to version 8.6.90 or 9.10.1-alpha.9 immediately to incorporate the required input type validation and cleanup scoping.
2. Audit web server logs for HTTP requests directed at installation endpoints that contain non-string data or unconventional JSON structures in installation fields, as these may indicate exploitation attempts.
3. Implement strict API gateway-level validation or WAF rules to reject requests containing non-string data types in fields expected to be strictly string-based.
