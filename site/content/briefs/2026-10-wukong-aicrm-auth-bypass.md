---
title: Missing Authorization Vulnerability in Wukong AICRM
slug: 2026-10-wukong-aicrm-auth-bypass
description: Wukong AICRM versions through 20260610 contain a missing authorization vulnerability that allows authenticated users to call administrative APIs, leading to account takeover via password reset.
date: "2026-10-14T04:36:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wukong:aicrm:*:*:*:*:*:*:*:*
tags:
  - web-application
  - privilege-escalation
  - auth-bypass
vendors:
  - Wukong
products:
  - AICRM (<= 20260610)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Wukong AICRM through 20260610 contains a missing authorization vulnerability that allows any authenticated user to call user, role, department and agent administration APIs.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can send POST requests to /managerUser/updateUser to reset the admin account's password and assign themselves the 'all' role, achieving full administrator account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-110207
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110207
rules:
  - title: Detect CVE-2026-110207 Exploitation Attempt - Unauthorized Access to User Management API
    description: Detects potential exploitation attempts of CVE-2026-110207 by monitoring for POST requests to the /managerUser/updateUser endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege-escalation
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Wukong AICRM instances to a version after 20260610
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability affects versions through 20260610
    - action: Deploy the webserver detection rule for /managerUser/updateUser
      owner: Detection Engineering
      due: 24h
      evidence: Artifact in brief provides actionable detection path
  hunt_leads:
    - lead: Search logs for unusual POST requests to /managerUser/updateUser
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Endpoint explicitly identified as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Patch Wukong AICRM to version 20260611 or later
      owner: IT Operations
      addresses: CVE-2026-110207
      evidence: Vulnerability exists up to 20260610
---

Wukong AICRM versions up to and including 20260610 are affected by a critical missing authorization vulnerability (CVE-2026-110207). The application fails to perform administrator-level permission checks on various administrative endpoints, including user, role, department, and agent management APIs. This flaw allows any authenticated user to interact with these sensitive functions. By sending a crafted POST request to the /managerUser/updateUser endpoint, an attacker can overwrite the administrator account's password and elevate their own privileges to the 'all' role. This vulnerability provides a straightforward path for unprivileged users to achieve full application administrative takeover. The vulnerability is highly exploitable, requiring only a valid standard user account to execute the administrative commands that lead to complete compromise of the AICRM instance.

## Attack Chain

1. Attacker authenticates to the Wukong AICRM platform using a low-privileged user account.
2. Attacker performs discovery to identify administrative API endpoints such as /managerUser/updateUser.
3. Attacker crafts a malicious HTTP POST request targeting the /managerUser/updateUser administrative endpoint.
4. The request includes parameters designed to reset the password of the administrative account.
5. The server processes the request without validating if the sender possesses administrative authorization.
6. The application updates the administrator password to a known value.
7. Attacker updates their account role to the 'all' role via the same or subsequent administrative API calls.
8. Attacker logs in as the administrator to gain full control over the CRM data and system configuration.

## Impact

Successful exploitation results in total administrative account takeover of the Wukong AICRM platform. This allows attackers to exfiltrate customer relationship data, modify system configurations, and manage user roles. Given the nature of CRM systems, this data often contains sensitive PII, business strategy, and client communication logs. Any instance of Wukong AICRM running version 20260610 or earlier is at risk.

## Recommendation

Prioritized actions for security teams:
* Patch or upgrade Wukong AICRM instances immediately to a version released after 20260610 that addresses CVE-2026-110207.
* Deploy web server detection rules to monitor for unauthorized POST requests to /managerUser/updateUser from standard user sessions.
* Audit logs for successful password changes or privilege escalations occurring through administrative API endpoints.
* Monitor for suspicious activity originating from low-privileged accounts that attempt to access management-related URI paths.
