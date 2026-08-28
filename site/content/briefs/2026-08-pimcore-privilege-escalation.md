---
title: Pimcore Studio API Privilege Escalation via Class Definition Endpoint
slug: 2026-08-pimcore-privilege-escalation
description: An insufficient permission check in the Pimcore studio-backend-bundle allows authenticated users with standard object-editing privileges to create class definitions, leading to unauthorized schema modification and server-side file creation.
date: "2026-08-28T21:14:22Z"
lastmod: "2026-08-28T21:14:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pimcore:studio_backend_bundle:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - cms
  - vulnerability
vendors:
  - Pimcore
products:
  - studio-backend-bundle (< 2025.4.6, 2026.1.0 - 2026.1.5)
  - studio-backend-bundle (< 2025.4.6, >= 2026.1.0 < 2026.1.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Studio API class definition creation endpoint is guarded by the objects permission instead of the classes permission, allowing any standard editor-level user to create class definitions without admin privileges.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability arises because the 'key' field in columnFilters is concatenated into SQL queries using manual backtick wrapping without adequate sanitization.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: An authenticated attacker can break out of the backtick quoting to inject malicious SQL commands, enabling the exfiltration of sensitive database data.
    confidence_band: high
cves:
  - id: CVE-2026-55212
    cvss: 7.1
    epss: 0.00351
references:
  - https://github.com/advisories/GHSA-f97c-ph8j-8vff
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55212
  - https://github.com/advisories/GHSA-79cw-hfcc-7mw9
rules:
  - title: Detect CVE-2026-55212 Exploitation - Unauthorized Class Definition Creation
    description: Detects potential exploitation of CVE-2026-55212 by monitoring POST requests to the vulnerable Studio API endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect CVE-2026-55208 Exploitation - Pimcore SQL Injection Attempt
    description: Detects exploitation attempts against Pimcore studio-backend-bundle via SQL injection payloads containing backticks and SQL keywords in the columnFilters key parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch pimcore/studio-backend-bundle to 2025.4.6 or 2026.1.6
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrade to these versions
  hunt_leads:
    - lead: Search logs for POST /pimcore-studio/api/class/definition/configuration-view/detail/create
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This endpoint is the direct target for the privilege escalation
  mitigation_plan:
    - priority: immediate
      action: Upgrade studio-backend-bundle to 2025.4.6 or 2026.1.6
      owner: IT Operations
      addresses: CVE-2026-55212
      evidence: Vendor advisory fix
updates:
  - at: "2026-08-28T21:14:34Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-55208 Exploitation - Pimcore SQL Injection Attempt'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-79cw-hfcc-7mw9
---

Pimcore Studio API, specifically the `pimcore/studio-backend-bundle`, contains a security flaw where the class definition creation endpoint is protected by the `objects` permission rather than the intended `classes` permission. This vulnerability, tracked as CVE-2026-55212, allows standard authenticated users with content editing rights to perform administrative actions. 

When exploited, this allows unauthorized users to generate new database tables and create PHP class files on the application server. This bypasses the security controls enforced in the Classic Admin interface. Additionally, the API lacks proper input validation for the `uid` parameter at the controller layer, which can lead to unhandled internal exceptions and potential information disclosure, such as stack traces, depending on the server's debug configuration. Affected versions are those earlier than 2025.4.6 and versions within the 2026.1.x range prior to 2026.1.6.

## Attack Chain

1. Attacker authenticates to the Pimcore application using credentials of a user account possessing only the `objects` permission.
2. Attacker interacts with the Studio API at `POST /pimcore-studio/api/class/definition/configuration-view/detail/create`.
3. The application's `CreateController` incorrectly validates the user's authorization against the `DATA_OBJECTS` permission.
4. Attacker provides a JSON payload containing a class name and an arbitrary `uid` value.
5. The API boundary performs only a basic empty-string check, allowing malformed or unauthorized `uid` data to proceed.
6. The Pimcore model layer processes the request, creating new database tables in the backend.
7. The system generates new PHP class files on the server based on the user-provided definition.
8. Final objective achieved: Unauthorized schema modification and potential execution of malicious object structures.

## Impact

Successful exploitation results in privilege escalation from a standard editor-level user to an administrative-level structural capability. An attacker can modify the application schema, potentially corrupting existing data models or introducing backdoored class structures. Furthermore, the lack of input validation on the `uid` parameter can lead to server-side exceptions, potentially exposing sensitive environment details via stack traces in error responses.

## Recommendation

Prioritized actions for security and IT teams:
- Patch Pimcore `studio-backend-bundle` to version 2025.4.6 or 2026.1.6 or later to address CVE-2026-55212.
- Audit existing class definitions for unauthorized entries created by non-admin users.
- Review web server logs for HTTP POST requests to `/pimcore-studio/api/class/definition/configuration-view/detail/create` originating from non-administrative user sessions.
- Disable debug mode in production environments to prevent the disclosure of internal stack traces triggered by malformed API inputs.
