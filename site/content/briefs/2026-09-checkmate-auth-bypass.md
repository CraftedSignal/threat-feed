---
title: Authorization Bypass in Checkmate via Missing Role Guard Middleware
slug: 2026-09-checkmate-auth-bypass
description: Checkmate versions through 3.11.0 contain an authorization bypass vulnerability (CVE-2026-85390) that allows read-only users to perform unauthorized administrative actions by accessing restricted routes.
date: "2026-09-03T19:22:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:checkmate:checkmate:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-application-vulnerability
vendors:
  - Checkmate
products:
  - Checkmate (<= 3.11.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Checkmate through 3.11.0 omits the isAllowed role guard middleware on maintenance-window, notification, and check-deletion routes, allowing read-only users to perform administrative actions.
    confidence_band: high
cves:
  - id: CVE-2026-85390
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85390
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Checkmate to version 3.11.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source confirms CVE-2026-85390 is fixed in versions after 3.11.0.
  hunt_leads:
    - lead: Identify unauthorized API calls to maintenance-window and check-deletion endpoints from read-only accounts
      technique_id: T1068
      data_needed:
        - Web server or application audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker uses these routes to silence alerts and erase evidence.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Checkmate to 3.11.1+
      owner: IT Operations
      addresses: CVE-2026-85390
      evidence: Official vulnerability notice.
---

Checkmate through version 3.11.0 contains an authorization bypass vulnerability (CVE-2026-85390) originating from the omission of the 'isAllowed' role guard middleware on specific administrative API routes. These affected routes include maintenance-window management, notification channel configurations, and monitor check deletion endpoints. The flaw effectively grants authenticated users with read-only privileges the ability to perform high-privilege administrative operations. By exploiting this gap in access control, an attacker can manipulate system-wide monitoring configurations, silence critical alerts by creating arbitrary maintenance windows, or modify notification delivery to suppress security event awareness. Furthermore, the ability to delete check history permits the removal of incident evidence, potentially impeding forensic investigations and post-incident response activities within affected environments.

## Impact

Successful exploitation allows read-only users to escalate their functional permissions, leading to potential loss of monitoring integrity and unauthorized removal of historical security telemetry. Organizations relying on Checkmate for infrastructure monitoring may face critical alert suppression and loss of audit trails, allowing other malicious activity to go undetected.

## Recommendation

1. Upgrade Checkmate to version 3.11.1 or later immediately to patch CVE-2026-85390.
2. Perform an audit of administrative activity logs, specifically targeting successful calls to maintenance-window, notification-update, or check-deletion endpoints by accounts lacking the 'Administrator' role.
3. Review audit logs for atypical monitor check deletion activity occurring from read-only service accounts or user sessions.
