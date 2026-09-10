---
title: Improper Access Control in Anchor CMS User Management
slug: 2026-09-anchor-cms-privilege-escalation
description: Anchor CMS versions 0.12.7 and earlier contain an improper access control vulnerability (CVE-2026-88959) allowing authenticated low-privileged users to escalate privileges by modifying administrative accounts.
date: "2026-09-10T17:07:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:anchor_cms:anchor_cms:*:*:*:*:*:*:*:*
vendors:
  - Anchor CMS
products:
  - Anchor CMS (<= 0.12.7)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Anchor CMS through 0.12.7 fails to enforce role-based access control in admin user-management endpoints, allowing any authenticated low-privilege user to create administrator accounts or modify existing ones.
    confidence_band: high
cves:
  - id: CVE-2026-88959
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88959
rules:
  - title: Detect CVE-2026-88959 Exploitation - Unauthorized Admin User Modification
    description: Detects potential exploitation of CVE-2026-88959 by identifying POST requests to administrative user management endpoints.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review logs for unauthorized access to /admin/users/add or /admin/users/edit
      owner: SOC
      due: 24h
      evidence: Source describes exploitation via these specific endpoints
  mitigation_plan:
    - priority: immediate
      action: Implement WAF or network restrictions for administrative interfaces
      owner: IT Operations
      addresses: CVE-2026-88959
      evidence: NVD vulnerability details
---

Anchor CMS versions 0.12.7 and earlier are vulnerable to a critical access control flaw in the administration module. The application fails to properly enforce role-based access control (RBAC) on user management endpoints. An authenticated user possessing a low-privilege role, such as editor or user, can bypass authorization checks to perform administrative actions. By sending a crafted POST request to specific management endpoints, an attacker can create new administrator accounts or modify the password of an existing administrator. This vulnerability allows for immediate privilege escalation to full administrative control over the CMS instance, facilitating complete site compromise, data exfiltration, or content modification.

## Attack Chain

1. Attacker obtains valid credentials for a low-privilege account (e.g., editor or user role) via phishing or credential stuffing.
2. Attacker logs into the Anchor CMS instance using the compromised low-privilege credentials.
3. Attacker discovers the admin/users/add or admin/users/edit endpoints through manual analysis of the application structure.
4. Attacker crafts a POST request targeting the admin/users/add endpoint to inject a new user with an administrator flag.
5. Alternatively, the attacker sends a POST request to the admin/users/edit endpoint to modify the credentials of an existing administrator account.
6. The application backend fails to validate the current user's administrative role, processing the request and updating the database accordingly.
7. The attacker authenticates as the newly created administrator or with the hijacked account credentials.
8. Final objective achieved: full administrative access is granted, allowing for site-wide configuration changes or data manipulation.

## Impact

Successful exploitation leads to full unauthorized administrative access to the affected CMS instance. Attackers can leverage this to modify site content, extract database information, or gain persistence within the server environment. This vulnerability affects all instances running versions 0.12.7 and earlier.

## Recommendation

Prioritized actions for administrators of the affected software:
- Immediately audit administrative user accounts for unauthorized additions or unexpected modifications (check application logs for requests to the admin/users/ endpoints).
- Restrict access to the Anchor CMS administration interface to known-secure management IP ranges via firewall/WAF.
- Monitor web application logs for POST requests to "/admin/users/add" and "/admin/users/edit" originating from low-privilege user sessions.
- Upgrade Anchor CMS to the latest version once a patch addressing CVE-2026-88959 is released by the maintainers.
