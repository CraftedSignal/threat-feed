---
title: Unauthenticated Privilege Escalation in Divi Membership Plugin
slug: 2026-10-divi-membership-privesc
description: The Divi Membership plugin for WordPress contains an unauthenticated privilege escalation vulnerability (CVE-2026-19652) allowing attackers to register as administrators through improper input validation.
date: "2026-10-02T14:24:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:divi_membership:divi_membership:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Divi Membership (<= 2.2.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This makes it possible for unauthenticated attackers to register a new account with the administrator role.
    confidence_band: high
cves:
  - id: CVE-2026-19652
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19652
rules:
  - title: Detect CVE-2026-19652 Exploitation - Registration with Elevated Role Hash
    description: Detects exploitation attempts by flagging suspicious POST requests to the Divi Membership registration endpoint containing bcrypt hash values in the form_id parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1078.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Divi Membership plugin to version 2.2.1 or higher
      owner: IT Operations
      due: 24h
      evidence: Plugin version 2.2.0 is vulnerable; upgrade requested
  hunt_leads:
    - lead: Search user creation logs for accounts registered with administrator roles in the past 30 days
      technique_id: T1078
      data_needed:
        - WordPress user registration audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit results in immediate administrator account creation
  mitigation_plan:
    - priority: immediate
      action: Disable public registration via Divi Membership if not required
      owner: IT Operations
      addresses: CVE-2026-19652
      evidence: Unauthenticated privilege escalation vector
---

The Divi Membership plugin for WordPress (versions 2.2.0 and below) is susceptible to an unauthenticated privilege escalation vulnerability. The root cause lies within the `dmem_form_submit_handler()` function, which incorrectly assigns user roles by iterating through available WordPress roles and performing a `password_verify()` check against an attacker-supplied bcrypt hash provided in the `form_id` POST parameter.

An unauthenticated attacker can exploit this by calculating the bcrypt hash of the string "administrator" and submitting it as the `form_id` parameter. Because the function lacks a whitelist of valid roles or validation of the input, the plugin assigns the elevated role to the newly registered account. Furthermore, when the `auto_login=on` parameter is included in the request, the attacker is automatically logged in as the new administrator, facilitating complete site takeover. The required security nonce is publicly exposed on pages hosting the registration form, allowing any unauthenticated visitor to obtain it and initiate the attack.

## Attack Chain

1. Attacker navigates to a public-facing page containing the Divi Membership registration form.
2. Attacker inspects the HTML source code to extract the publicly available WordPress nonce required for form submission.
3. Attacker computes the bcrypt hash of the desired role, in this case, "administrator".
4. Attacker constructs a POST request to the registration handler containing the stolen nonce.
5. Attacker includes the `form_id` POST parameter populated with the computed bcrypt hash and sets the `auto_login` parameter to `on`.
6. The `dmem_form_submit_handler()` function processes the input, validates the hash, and assigns the administrator role to the user account being created.
7. The application returns a successful registration response, and the `auto_login` logic grants the attacker an active session with administrator privileges.
8. Attacker gains full control of the WordPress instance for further exploitation or exfiltration.

## Impact

Successful exploitation results in total site compromise. An attacker can gain administrator access to the WordPress environment, allowing them to install malicious plugins, modify site content, exfiltrate user data, or use the server as a base for further lateral movement within the network. All instances of the Divi Membership plugin at version 2.2.0 or earlier are vulnerable.

## Recommendation

1. Upgrade the Divi Membership plugin to the latest patched version immediately.
2. Audit user accounts for unauthorized administrators created within the last 30 days.
3. Monitor web server logs for suspicious POST requests targeting the plugin's registration handler.
4. Implement WAF rules to detect and block requests where the `form_id` parameter contains values inconsistent with expected numeric or alphanumeric formatting.
