---
title: SQL Injection Vulnerability in Evergreen OpenSRF Service
slug: 2026-08-evergreen-sql-injection
description: Evergreen versions up to 3.17-beta1 contain a SQL injection vulnerability in the OpenSRF service, allowing remote unauthenticated attackers to execute arbitrary database queries.
date: "2026-08-16T02:22:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - sql-injection
  - cve-2026-19926
vendors:
  - Evergreen
products:
  - OpenSRF Service
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The affected element is an unknown function of the file /osrf-gateway-v1 of the component open-ils.fielder OpenSRF Service. Such manipulation leads to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-19926
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19926
rules:
  - title: Detects CVE-2026-19926 Exploitation - SQL Injection via /osrf-gateway-v1
    description: Detects potential SQL injection attempts targeting the /osrf-gateway-v1 endpoint in Evergreen OpenSRF
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
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Upgrade Evergreen software to the latest patched version
      owner: IT Operations
      due: 24h
      evidence: Vendor recommendation for CVE-2026-19926
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /osrf-gateway-v1 via WAF or web server configuration
      owner: Security Team
      addresses: CVE-2026-19926
      evidence: Vulnerability exists in the exposed /osrf-gateway-v1 endpoint
---

A critical SQL injection vulnerability, identified as CVE-2026-19926, exists in the OpenSRF Service component of the Evergreen integrated library system. The flaw specifically affects the '/osrf-gateway-v1' endpoint and arises from improper sanitization of user-supplied input. Publicly available exploit code currently exists, enabling remote, unauthenticated attackers to manipulate database queries. This vulnerability allows for unauthorized data access or modification within the back-end database of the Evergreen implementation. Affected installations include versions 3.14.11, 3.15.11, 3.16.5, and 3.17-beta1. Organizations should upgrade to versions 3.14.12, 3.15.12, 3.16.6, or 3.17-beta2 immediately to mitigate the risk.

## Impact

Successful exploitation of this vulnerability permits unauthorized actors to interact with the underlying database, potentially leading to full exfiltration of library records, user information, or system configuration data. Given the remote and unauthenticated nature of the attack, this represents a high risk to availability and confidentiality for institutions deploying the Evergreen system.

## Recommendation

- Upgrade Evergreen instances to version 3.14.12, 3.15.12, 3.16.6, or 3.17-beta2 immediately to remediate CVE-2026-19926.
- Implement strict ingress filtering on the web server to restrict access to the '/osrf-gateway-v1' endpoint to only trusted internal IP ranges.
- Audit database access logs for unusual patterns or syntax typical of SQL injection attempts, such as UNION statements or comment sequences, originating from the web server process.
