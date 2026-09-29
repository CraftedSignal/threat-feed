---
title: Broken Access Control in Liberu CRM via Team Invitation Logic
slug: 2026-09-liberu-crm-broken-access-control
description: Liberu CRM versions 0.9.1 through 10.0.0 are vulnerable to privilege escalation via a broken access control flaw in the team invitation workflow, allowing users with pending invites to provision unauthorized administrator accounts.
date: "2026-09-29T20:30:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:liberu:crm:*:*:*:*:*:*:*:*
vendors:
  - Liberu
products:
  - Liberu CRM (0.9.1 - 9.9.9)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The flaw allows a user with a pending team invitation to escalate privileges by inviting additional attacker-controlled accounts with admin roles.
    confidence_band: high
cves:
  - id: CVE-2026-61519
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61519
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Liberu CRM to 10.0.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source identifies 10.0.0 as the version containing the fix for CVE-2026-61519.
  hunt_leads:
    - lead: Search logs for POST requests to team-invitation endpoints from non-admin users adding members with admin roles
      technique_id: T1078
      data_needed:
        - Web server logs (POST /team-invitations)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation involves a POST request to the team-invitations route specifying the admin role.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Liberu CRM 10.0.0
      owner: IT Operations
      addresses: CVE-2026-61519
      evidence: Official fix for the identified broken access control vulnerability.
---

Liberu CRM versions 0.9.1 through 10.0.0 contain a broken access control vulnerability (CVE-2026-61519) within the `TeamPolicy::addTeamMember()` function. The vulnerability stems from a flawed authorization predicate that incorrectly grants invitation rights based solely on the presence of a pending team invitation. An attacker holding a valid pending invitation for a low-privilege team role can exploit this logic to invite secondary attacker-controlled accounts with elevated administrative privileges. Upon the acceptance of these crafted invitations, the secondary accounts are provisioned with full administrative create, read, update, and delete access to all team-scoped data. This vulnerability bypasses intended privilege-level validation within the `InviteTeamMember` component, presenting a significant risk of unauthorized data access and integrity compromise for organizations utilizing the affected software.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to achieve full administrative control over team-scoped data. This can lead to the exfiltration of sensitive organizational information, modification of team records, and long-term persistence within the application environment. The severity is marked as high (CVSS 8.8) due to the ease of exploitation and the depth of access granted upon compromise.

## Recommendation

- Upgrade Liberu CRM to version 10.0.0 or later immediately to apply the patch for CVE-2026-61519.
- Audit existing team memberships for anomalies, specifically checking for recently added administrative accounts that do not correlate with legitimate organizational hiring or team changes.
- Review web server logs for suspicious POST requests to the `team-invitations` API endpoint that contain elevated role parameters associated with users who lack administrative status.
