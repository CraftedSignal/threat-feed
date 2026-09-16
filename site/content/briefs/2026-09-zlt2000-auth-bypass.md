---
title: Authorization Bypass in zlt2000 microservices-platform
slug: 2026-09-zlt2000-auth-bypass
description: A default configuration vulnerability in zlt2000 microservices-platform through 6.0.0 disables URL permission checks, allowing authenticated users to perform unauthorized administrative actions.
date: "2026-09-16T15:50:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zlt2000:microservices-platform:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - web-application
vendors:
  - zlt2000
products:
  - microservices-platform (<= 6.0.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Privilege Escalation Vulnerability
    evidence: Authenticated users with no roles can access administrative APIs including user management, role assignment, and Elasticsearch index operations by bypassing the disabled authorization enforcement.
    confidence_band: high
cves:
  - id: CVE-2026-92466
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92466
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Set 'zlt.security.auth.urlPermission.enable' to 'true' in the application configuration
      owner: IT Operations
      due: 24h
      evidence: Source documentation identifies this as the remediation for the misconfiguration.
  hunt_leads:
    - lead: Search API access logs for successful requests to administrative endpoints from non-admin user sessions.
      technique_id: T1068
      data_needed:
        - Web server or application access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The flaw allows unauthorized users to access administrative APIs.
  mitigation_plan:
    - priority: immediate
      action: Enable URL permission checks via platform configuration
      owner: IT Operations
      addresses: CVE-2026-92466
      evidence: Source states that the flag defaults to false, disabling permission checks.
---

The zlt2000 microservices-platform, version 6.0.0 and earlier, contains a critical security configuration vulnerability (CVE-2026-92466). The platform defaults the 'zlt.security.auth.urlPermission.enable' configuration flag to 'false'. When this flag is disabled, the platform fails to enforce URL-level permission checks for authenticated sessions. This flaw essentially renders the role-based access control (RBAC) mechanism ineffective, allowing any successfully authenticated user - regardless of their assigned roles or privileges - to interact with sensitive administrative endpoints. This exposure permits unauthorized users to perform administrative tasks, including managing user accounts, modifying role assignments, and interacting directly with Elasticsearch index operations, posing a significant risk of privilege escalation and unauthorized data manipulation within the microservices environment.

## Impact

The vulnerability allows for complete unauthorized administrative access to the platform's backend services. An attacker who gains low-privileged credentials can escalate privileges to perform administrative actions, potentially leading to full system compromise, exfiltration of data via Elasticsearch index access, and the modification of user accounts to maintain persistent, high-privileged access.

## Recommendation

Prioritized actions for security and IT teams:

* Apply the configuration update by setting 'zlt.security.auth.urlPermission.enable' to 'true' in the platform's configuration file immediately.
* Audit administrative audit logs to identify any unexpected access to sensitive API endpoints such as '/api/user/manage' or Elasticsearch management interfaces initiated by low-privileged user accounts.
* Review all user accounts and role assignments for unauthorized modifications performed during the period the platform was running with the default configuration.
