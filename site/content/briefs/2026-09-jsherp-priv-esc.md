---
title: Privilege Escalation in jshERP 3.6 via updateOneValueByKeyIdAndType
slug: 2026-09-jsherp-priv-esc
description: jshERP 3.6 contains an improper access control vulnerability in the updateOneValueByKeyIdAndType endpoint allowing authenticated users to escalate privileges to tenant administrator.
date: "2026-09-21T20:30:00Z"
lastmod: "2026-09-21T20:30:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jsherp:jsherp:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-application
  - authorization-bypass
vendors:
  - jshERP
products:
  - jshERP (3.6)
  - jshERP (<= 3.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated attacker can exploit this flaw by sending a crafted POST request to modify their own user privileges, specifically targeting the 'UserRole' type to elevate their account.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: Attackers can submit a request with an arbitrary target user ID to reset that account's password to a known default value.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: enabling unauthorized access to other user accounts including administrators.
    confidence_band: high
cves:
  - id: CVE-2026-94411
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94411
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94412
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94495
rules:
  - title: Detect CVE-2026-94411 Exploitation - Privilege Escalation in jshERP
    description: Detects exploitation of CVE-2026-94411 by monitoring for POST requests to the vulnerable API endpoint with parameters used for privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detects CVE-2026-94412 Exploitation - Password Reset Authorization Bypass
    description: Detects potential exploitation attempts against the /user/resetPwd endpoint by monitoring for POST requests that may indicate unauthorized account targeting
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1531
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule for CVE-2026-94411 detection
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms endpoint-based exploitation
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate jshERP 3.6 instances
      owner: IT Operations
      addresses: CVE-2026-94411
      evidence: NVD vulnerability entry
updates:
  - at: "2026-09-21T20:30:09Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-94412 Exploitation - Password Reset Authorization Bypass'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-94412
  - at: "2026-09-21T20:30:16Z"
    level: L2
    summary: added coverage for jshERP (<= 3.6)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-94495
---

jshERP version 3.6 is vulnerable to a privilege escalation flaw located within the updateOneValueByKeyIdAndType endpoint. This vulnerability stems from improper access control, enabling an authenticated low-privilege tenant user to modify their own account permissions. By submitting a crafted POST request, an attacker can specify the type parameter as UserRole and supply a chosen role ID list, effectively granting themselves administrative privileges within the tenant environment. This vulnerability, tracked as CVE-2026-94411, carries a CVSS v3.1 base score of 8.8. It represents a significant security risk for organizations relying on jshERP for multi-tenant enterprise resource planning, as it allows for horizontal and vertical privilege escalation without requiring existing administrative access.

## Impact

Successful exploitation allows a low-privileged tenant user to gain full administrative control over their tenant account. This results in the potential for unauthorized data access, modification, or deletion of sensitive business information and configuration settings stored within the jshERP instance. Given the nature of the application as an ERP system, unauthorized administrative access poses a severe risk to data integrity and business operations.

## Recommendation

Prioritize remediation by identifying and patching instances of jshERP 3.6. If a patch is not immediately available, restrict access to the web interface from untrusted networks and audit logs for unauthorized requests to the updateOneValueByKeyIdAndType endpoint.

## Detection

Detecting this exploitation requires monitoring web server logs for suspicious POST requests targeting the identified API endpoint.

- Monitor web access logs for HTTP POST requests to the /updateOneValueByKeyIdAndType endpoint where the request body contains 'type=UserRole' and parameters indicative of role modification.
- Audit user management activities and privilege changes within the application logs to identify anomalous account elevation events.
