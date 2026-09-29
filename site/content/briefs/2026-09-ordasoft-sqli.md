---
title: Unauthenticated SQL Injection in OrdaSoft Real Estate Manager
slug: 2026-09-ordasoft-sqli
description: OrdaSoft Real Estate Manager for Joomla versions 6.7.8 and earlier are vulnerable to unauthenticated SQL injection via the 'order_field' parameter, enabling unauthorized database access and data exfiltration.
date: "2026-09-29T00:27:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ordasoft:real_estate_manager:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - sqli
  - joomla
vendors:
  - OrdaSoft
products:
  - Real Estate Manager (<= 6.7.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The OrdaSoft Real Estate Manager extension contains a critical unauthenticated SQL injection vulnerability (CVE-2026-100752).
    confidence_band: high
cves:
  - id: CVE-2026-100752
  - id: CVE-2026-100753
rules:
  - title: Detects CVE-2026-100752 Exploitation - SQL Injection in OrdaSoft Real Estate Manager
    description: Detects exploitation attempts against the OrdaSoft Real Estate Manager extension by identifying SQL injection patterns in the order_field parameter.
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
    - action: Upgrade all OrdaSoft Real Estate Manager instances to 6.7.9 or later
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability fixed in 6.7.9+
  hunt_leads:
    - lead: Search logs for suspicious order_field parameters containing SQL keywords
      technique_id: T1190
      data_needed:
        - web_server_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The PoC uses order_field to perform SQL injection
  mitigation_plan:
    - priority: immediate
      action: Patch OrdaSoft extensions
      owner: IT Operations
      addresses: CVE-2026-100752
      evidence: Upgrade to 6.7.9+
---

OrdaSoft Real Estate Manager (Free), a popular property management extension for Joomla, contains a critical unauthenticated SQL injection vulnerability tracked as CVE-2026-100752. The flaw exists in the component 'com_realestatemanager' (specifically in 'site/realestatemanager.php'), where the 'order_field' parameter is unsafely concatenated into an SQL ORDER BY clause. Because the application lacks allow-listing or proper input validation for this parameter, an unauthenticated attacker can inject arbitrary SQL commands. This can lead to full database enumeration, extraction of sensitive information such as user credentials, and potential administrative compromise of the underlying Joomla instance. A related reflected XSS vulnerability (CVE-2026-100753) was disclosed in the same security update train. Defenders must prioritize upgrading all OrdaSoft components to version 6.7.9 or later, as functional PoC code for this SQL injection is publicly available.

## Attack Chain

1. Attacker performs discovery to identify Joomla sites running the 'com_realestatemanager' extension using Dorks or automated scanners.
2. Attacker verifies the target version by requesting 'site/realestatemanager.php' or checking the manifest file at '/administrator/components/com_realestatemanager/realestatemanager.xml'.
3. Attacker crafts a malicious HTTP GET or POST request targeting the 'showCategory' task in 'com_realestatemanager'.
4. Attacker injects a payload into the 'order_field' parameter (e.g., using UNION-based or error-based SQL injection techniques).
5. The Joomla server processes the malicious input and executes the injected SQL command against the database due to lack of input sanitization.
6. The backend database returns query results (e.g., database version, table contents, or user hashes) embedded in the HTTP response.
7. Attacker parses the response to exfiltrate database contents or further escalate privileges within the Joomla environment.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary data from the database, including site configuration, user lists, and password hashes. Given that the extension is used to manage real estate listings and customer data, this poses a significant risk to data privacy and site integrity. Organizations failing to patch are at high risk of full database exfiltration.

## Recommendation

1. Upgrade OrdaSoft Real Estate Manager to version 6.7.9 or later immediately to patch CVE-2026-100752 and CVE-2026-100753.
2. Audit all OrdaSoft Joomla extensions for similar vulnerabilities, as other components in the same vendor suite were patched concurrently.
3. Deploy web application firewall (WAF) rules to inspect the 'order_field' parameter in requests to 'com_realestatemanager' for SQL injection patterns (e.g., SELECT, UNION, or comment sequences).
4. Use the provided Sigma rule to monitor for malicious injection attempts against the target component.
