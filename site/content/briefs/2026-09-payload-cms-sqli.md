---
title: Blind SQL Injection Vulnerability in Payload CMS
slug: 2026-09-payload-cms-sqli
description: Payload CMS versions prior to 3.73.0 are vulnerable to Blind SQL Injection via maliciously crafted JSON filter inputs processed by the Drizzle database adapter.
date: "2026-09-01T14:31:32Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:payloadcms:payload_cms:*:*:*:*:*:*:*:*
  - cpe:2.3:a:payloadcms:payload:*:*:*:*:*:node.js:*:*
tags:
  - webapps
  - sqli
  - vulnerability
vendors:
  - Payload CMS
products:
  - Payload CMS (< 3.73.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Payload CMS versions prior to 3.73.0 contain a Blind SQL Injection vulnerability when processing where filters.
    confidence_band: high
cves:
  - id: CVE-2026-25544
    cvss: 9.8
    epss: 0.00453
references:
  - https://www.exploit-db.com/exploits/52671
rules:
  - title: Detect CVE-2026-25544 Exploitation - Blind SQL Injection via API Filter
    description: Detects exploitation attempts against CVE-2026-25544 where attackers inject SQL metacharacters into the 'where' filter parameter of API requests.
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Payload CMS to 3.73.0 or later
      owner: IT Operations
      due: 48h
      evidence: Vendor release fixes CVE-2026-25544
  hunt_leads:
    - lead: Search logs for unusual URL-encoded characters in API 'where' parameters
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploit uses specific JSON structures to trigger SQLi
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2026-25544
      owner: IT Operations
      addresses: CVE-2026-25544
      evidence: Patch version 3.73.0 addresses the vulnerability
---

Payload CMS versions prior to 3.73.0 contain a critical Blind SQL Injection vulnerability, identified as CVE-2026-25544. The vulnerability occurs during the processing of 'where' filters in API requests, specifically when the application interacts with JSON or RichText fields utilizing the Drizzle database adapter. An attacker can supply a crafted JSON payload within the 'where' filter parameter to manipulate generated JSONPath expressions, potentially allowing for unauthorized data exfiltration or database state inference. Given that a functional proof-of-concept exploit is publicly available, organizations running impacted versions are at an elevated risk of exploitation.

## Attack Chain

1. Attacker identifies an internet-facing endpoint running Payload CMS, such as /api/posts.
2. Attacker probes the 'where' query parameter to determine if it accepts complex JSON structures.
3. Attacker crafts a malicious JSON payload containing SQL injection characters (e.g., '|| @ == @ || @ == ') to target specific database fields.
4. The application receives the request and passes the attacker-supplied 'where' filter to the Drizzle database adapter.
5. The Drizzle adapter fails to sanitize the input, incorporating the malicious SQL syntax into the query executed against the backend PostgreSQL database.
6. The backend database processes the injected query and returns a modified result set, indicating successful blind SQL injection through time-based or boolean-based inference.
7. Attacker iteratively exfiltrates data from the database by observing the application's responses to varying injected conditions.

## Impact

Successful exploitation allows unauthenticated attackers to infer sensitive information from the underlying PostgreSQL database. This can lead to unauthorized data disclosure, including user credentials, metadata, or other proprietary application data stored within the CMS.

## Recommendation

Prioritize the following actions to mitigate this threat:
- Upgrade all instances of Payload CMS to version 3.73.0 or later to patch CVE-2026-25544.
- Implement strict input validation on the API gateway level to block requests containing anomalous characters or SQL operators within 'where' filter parameters if an immediate upgrade is not feasible.
- Monitor web server logs for suspicious requests to API endpoints that contain high concentrations of special characters in the 'where' query parameter.
