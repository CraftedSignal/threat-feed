---
title: Unauthenticated Privilege Escalation in KiviCare WordPress Plugin
slug: 2026-08-kivicare-vuln
description: The KiviCare WordPress plugin (<= 4.5.1) is vulnerable to unauthenticated account creation via its REST API, allowing attackers to escalate privileges to doctor or receptionist roles and access sensitive patient PHI.
date: "2026-08-15T05:25:51Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - KiviCare
products:
  - KiviCare (<= 4.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1136
    technique_name: Create Account
    evidence: The unauthenticated registration endpoint allows an anonymous attacker to create doctor or receptionist accounts with a self-chosen password.
    confidence_band: high
cves:
  - id: CVE-2026-13610
    cvss: 7.5
    epss: 0.00149
references:
  - https://sploitus.com/exploit?id=CBD72344-F142-56B5-8556-306D865B45EF
rules:
  - title: Detect CVE-2026-13610 Exploitation - Unauthorized KiviCare Registration
    description: Detects unauthorized attempts to register users via the KiviCare API with privileged roles.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1136.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block access to /wp-json/kivicare/v1/auth/register for external traffic
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable to unauthenticated registration
  hunt_leads:
    - lead: Search user database for accounts with roles kiviCare_doctor or kiviCare_receptionist created since 2026-08-15
      technique_id: T1136.001
      data_needed:
        - WordPress database logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Evidence of account creation via vulnerable API
  mitigation_plan:
    - priority: immediate
      action: Upgrade KiviCare to version > 4.5.1
      owner: IT Operations
      addresses: CVE-2026-13610
      evidence: Official advisory states vulnerability exists in 4.5.1 and lower
---

KiviCare (a Clinic & Patient Management System plugin for WordPress) contains a critical improper privilege management vulnerability, identified as CVE-2026-13610. The vulnerability exists within the REST API registration endpoint (`/wp-json/kivicare/v1/auth/register`), which fails to properly authenticate or authorize requests. 

An unauthenticated attacker can interact with this endpoint to create new user accounts. By manipulating the `user_role` parameter, the attacker can force the creation of accounts with elevated permissions, specifically `kiviCare_doctor` or `kiviCare_receptionist`, instead of the intended `kiviCare_patient` role. Furthermore, the application fails to enforce the `patient_role_only` parameter, and the permission callback defaults to allowing the action without performing nonce or session validation. This allows an attacker to gain a valid administrative foothold in the WordPress instance and access sensitive patient protected health information (PHI) such as appointments, prescriptions, and billing records.

## Attack Chain

1. Attacker performs reconnaissance to identify a target site running the vulnerable KiviCare WordPress plugin.
2. Attacker interacts with the unauthenticated registration endpoint at `POST /wp-json/kivicare/v1/auth/register`.
3. Attacker bypasses the E2EE mechanism by retrieving the `server-key` via the publicly accessible `ConfigController`.
4. Attacker sends a crafted JSON payload containing a chosen username, email, password, and the elevated `user_role` (e.g., `kiviCare_doctor`).
5. The plugin fails to perform a permission callback check, authorizing the request due to a default `return true` logic flaw.
6. The `wp_insert_user()` function creates the account, and `setRole()` assigns the requested elevated role to the new user.
7. Attacker authenticates with the newly created account via the REST API.
8. Attacker leverages the elevated role to query API endpoints, exfiltrating patient PHI and performing administrative actions.

## Impact

Successful exploitation allows unauthenticated attackers to create unauthorized privileged accounts on vulnerable WordPress sites. This results in full access to the medical clinic's management dashboard, including sensitive patient PHI such as medical history, prescriptions, and financial data, leading to severe privacy violations and compliance risks.

## Recommendation

Prioritized actions for detection engineering and security teams:
- Deploy the WAF rules below to block unauthorized registration requests to the vulnerable API endpoint.
- Audit the WordPress user database for unauthorized accounts assigned to the `kiviCare_doctor` or `kiviCare_receptionist` roles created after August 15, 2026.
- Patch the KiviCare plugin to a version above 4.5.1 immediately.
- If a patch is unavailable, disable new user registrations or explicitly restrict access to the `/wp-json/kivicare/v1/` endpoint at the web server level.
