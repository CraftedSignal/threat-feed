---
brief_id: brief-2026-10-21-php-travel-agency-system-auth-bypass
event_id: brief-2026-10-21-php-travel-agency-system-auth-bypass
revision: 2
activity_at: "2026-10-27T20:02:31Z"
revision_history:
  - revision: 2
    at: "2026-10-27T20:02:31Z"
    checksum: sha256:f13218e1b31ec1e4a85907369f31345dafbb9227271201f81f036a77b9b41018
    summary: added CVE-2026-114441 +1
    changed_fields:
      - action_plan
      - affected_products
      - claim_state
      - cpes
      - cves
      - lastmod
      - priority_score
      - priority_signals
      - references
      - rules
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-117516
title: 'oretnom23 php-travel-agency-system: Authentication bypass via user_id manipulation (CVE-2026-114439)'
slug: 2026-10-php-travel-agency-system-auth-bypass
description: An authentication bypass vulnerability in the php-travel-agency-system allows remote attackers to gain unauthorized access by manipulating the user_id argument in admin/session.php.
date: "2026-10-21T23:48:42Z"
lastmod: "2026-10-27T20:01:02Z"
type: advisory
claim_state: <nil>
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
  validation_status: No vendor patch available, remediation relies on compensating controls
cpes:
  - cpe:2.3:a:oretnom23:php-travel-agency-system:*:*:*:*:*:*:*:*
  - cpe:2.3:a:oretnom23:php-travel-agency-system:4e28b8f84d72420373dd15c3ae32900beb7e0635:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - cve-2026-114439
vendors:
  - oretnom23
products:
  - php-travel-agency-system (rolling release)
  - php-travel-agency-system
  - php-travel-agency-system (4e28b8f84d72420373dd15c3ae32900beb7e0635)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument user_id can lead to missing authentication. It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-114439
    cvss: 7.3
    epss: 0.00537
    kev_status: "false"
  - id: CVE-2026-117515
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-117516
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-114441
    cvss: 7.3
    epss: 0.00419
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114439
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114441
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117515
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117516
rules:
  - title: Detects CVE-2026-117515 Exploitation - SQL Injection in traceapplication.php
    description: Detects SQL injection attempts by searching for common SQL keywords and metacharacters in the query string of requests directed to traceapplication.php
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
    - action: Restrict external access to /admin/ path for php-travel-agency-system
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows unauthenticated remote access via admin/session.php
    - action: Inventory all deployments of php-travel-agency-system
      owner: IT Operations
      due: 24h
      evidence: Vulnerability in project code requires identification of affected hosts.
  hunt_leads:
    - lead: Identify HTTP requests to /admin/session.php containing anomalous user_id parameters
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Manipulation of user_id argument in admin/session.php enables authentication bypass
    - lead: Inspect access logs for SQL injection payloads in traceapplication.php
      technique_id: T1190
      data_needed:
        - web_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The manipulation of the argument Search results in sql injection.
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block or inspect unauthorized access attempts to the admin session handler
      owner: IT Operations
      addresses: CVE-2026-114439
      evidence: No vendor patch available; requires external filtering
    - priority: immediate
      action: Implement WAF filtering for traceapplication.php or restrict access
      owner: IT Operations
      addresses: CVE-2026-117515
      evidence: Public exploit exists and project has not responded to vulnerability report.
updates:
  - at: "2026-10-21T23:48:54Z"
    level: L2
    summary: added coverage for php-travel-agency-system
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-114441
  - at: "2026-10-27T20:01:01Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-117515 Exploitation - SQL Injection in traceapplication.php'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-117515
  - at: "2026-10-27T20:01:02Z"
    level: L2
    summary: added CVE-2026-114441 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-117516
---

CVE-2026-114439 affects the php-travel-agency-system component responsible for session handling. The vulnerability exists in 'admin/session.php', where insufficient validation of the 'user_id' argument allows an attacker to bypass authentication mechanisms. The project follows a rolling release model, and no specific patch or fixed version is currently available. The maintainers have been notified but have not provided a response or a resolution.

## Impact

Successful exploitation allows a remote, unauthenticated attacker to bypass authentication controls and potentially gain administrative access to the travel agency system.

## Recommendation

- Inventory all instances of 'php-travel-agency-system' within your environment.
- Restrict access to the 'admin/' directory to known, trusted IP addresses via web application firewall or network-level access controls until a security update is provided by the vendor.
- Implement request logging for all calls to 'admin/session.php' to identify potential exploitation attempts characterized by non-standard 'user_id' parameters.
- If the application is not business-critical, disable it until the vulnerability is addressed by the maintainer.
