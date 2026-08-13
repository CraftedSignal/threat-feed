---
title: Unauthenticated SQL Injection and Authentication Bypass in Hongjing e-HR
slug: 2026-08-hongjing-ehr-sql-injection
description: Hongjing e-HR contains an unauthenticated SQL injection and path traversal vulnerability (CVE-2024-58374) allowing attackers to bypass authentication and exfiltrate database contents via the getSdutyTree servlet.
date: "2026-08-13T18:56:47Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - vulnerability
  - sql-injection
  - web-application
  - cve-2024-58374
vendors:
  - Hongjing
products:
  - e-HR
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Hongjing e-HR contains an unauthenticated SQL injection vulnerability in the getSdutyTree servlet endpoint that allows remote unauthenticated attackers to access protected resources.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attackers can inject UNION-based SQL payloads... to retrieve sensitive database contents including user credentials.
    confidence_band: high
cves:
  - id: CVE-2024-58374
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-58374
rules:
  - title: Detects CVE-2024-58374 Exploitation - Path Traversal and SQL Injection
    description: Detects exploitation attempts against Hongjing e-HR by identifying URI path traversal patterns alongside SQL injection markers in the codeitemid parameter.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch Hongjing e-HR installations for CVE-2024-58374
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Search web logs for URI patterns containing '../' combined with 'getSdutyTree'
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Observed exploitation techniques in summary
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block path traversal and SQL injection payloads targeting e-HR servlet endpoints
      owner: Security Engineering
      addresses: CVE-2024-58374
      evidence: Technical analysis of the vulnerability
---

Hongjing e-HR software is affected by an unauthenticated vulnerability in the getSdutyTree servlet. Attackers leverage a path traversal sequence within the request URI to bypass the oauthservlet authentication filter, allowing them to reach protected endpoints without credentials. Once authentication is bypassed, attackers can perform UNION-based SQL injection by manipulating the unsanitized codeitemid parameter. This allows for the unauthorized retrieval of sensitive information from the backend Microsoft SQL Server database, including user credentials. Exploitation in the wild was first identified by the Shadowserver Foundation on July 30, 2024. This vulnerability poses a significant risk to organizations using the e-HR platform as it facilitates full database exfiltration through unauthenticated access.

## Attack Chain

1. Attacker sends a crafted HTTP GET request to the getSdutyTree servlet endpoint.
2. Request includes a path traversal sequence (e.g., ../) in the URI to bypass the oauthservlet authentication filter.
3. The application fails to validate the request path, granting access to the endpoint without an active session.
4. Attacker includes a malicious UNION-based SQL payload within the codeitemid parameter.
5. The application passes the unsanitized input directly to the backend Microsoft SQL Server database query.
6. The database executes the injected SQL command and returns the results of the UNION query within the application response.
7. Attacker parses the response to exfiltrate user credentials and other sensitive data.

## Impact

Successful exploitation allows remote, unauthenticated attackers to bypass security controls and perform unauthorized data exfiltration from the e-HR database. This can lead to a complete compromise of user credentials and the exposure of sensitive organizational information, potentially facilitating further lateral movement or additional system access.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
* Deploy webserver logs monitoring to detect URI patterns containing path traversal sequences directed at the getSdutyTree servlet.
* Audit Microsoft SQL Server database logs for unexpected UNION SELECT or sensitive information schema queries originating from the application service account.
* Apply vendor-supplied patches for CVE-2024-58374 on all internet-facing e-HR instances immediately.
* Inspect web server access logs for anomalous GET requests containing non-alphanumeric characters or SQL keywords in the codeitemid parameter.
