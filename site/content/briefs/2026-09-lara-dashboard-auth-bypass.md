---
title: Authentication Bypass in Lara Dashboard
slug: 2026-09-lara-dashboard-auth-bypass
description: Lara Dashboard versions prior to 1.3.0 are vulnerable to an authentication bypass in the screenshot-login route that permits unauthenticated access to any user account when APP_ENV is not set to production.
date: "2026-09-05T13:31:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:lara_dashboard_project:lara_dashboard:*:*:*:*:*:*:*:*
products:
  - Lara Dashboard (< 1.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Lara Dashboard before 1.3.0 contains an authentication bypass vulnerability in the screenshot-login route that allows unauthenticated attackers to authenticate as any user
    confidence_band: high
cves:
  - id: CVE-2026-86184
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86184
rules:
  - title: Detects CVE-2026-86184 Exploitation - Unauthenticated Access via screenshot-login
    description: Detects exploitation attempts against CVE-2026-86184 by monitoring for GET requests to the screenshot-login route
    platform: sigma
    severity: critical
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Lara Dashboard to 1.3.0
      owner: IT Operations
      due: 24h
      evidence: Lara Dashboard before 1.3.0 contains an authentication bypass vulnerability
    - action: Review web server logs for suspicious /screenshot-login/ activity
      owner: SOC
      due: 24h
      evidence: Unauthenticated attackers can request the GET /screenshot-login/{email} endpoint
  mitigation_plan:
    - priority: immediate
      action: Set APP_ENV=production
      owner: IT Operations
      addresses: CVE-2026-86184
      evidence: Vulnerability triggers when APP_ENV is not production
---

Lara Dashboard versions prior to 1.3.0 contain an authentication bypass vulnerability in the screenshot-login route that allows unauthenticated attackers to authenticate as any user by specifying their email address. This vulnerability is active when the application environment (APP_ENV) is configured to anything other than 'production'. By sending a crafted GET request to the /screenshot-login/{email} endpoint, an unauthenticated attacker can obtain a fully authenticated session for the specified user account. This provides the attacker with immediate access to sensitive system administration panels, application settings, and database contents. Furthermore, the elevated access granted by this bypass allows for the use of the module installer to execute arbitrary code on the underlying server, presenting a significant risk to organizational infrastructure.

## Impact

Successful exploitation allows for full account takeover of any user, including administrative accounts. Attackers can leverage this access to exfiltrate sensitive data from the database, modify system configurations, and achieve remote code execution via legitimate management modules. This vulnerability exposes the entire application instance to total compromise.

## Recommendation

* Upgrade Lara Dashboard to version 1.3.0 or later immediately to resolve CVE-2026-86184.
* Ensure the production application environment is explicitly set to 'production' (APP_ENV=production) in all deployment configurations to disable the vulnerable debug/development route.
* Audit access logs for unauthorized GET requests to the /screenshot-login/ path, especially those originating from external or untrusted network segments.
