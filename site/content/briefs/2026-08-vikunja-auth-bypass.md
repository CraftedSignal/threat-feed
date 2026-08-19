---
title: Principal-Type Confusion Vulnerability in Vikunja
slug: 2026-08-vikunja-auth-bypass
description: Vikunja versions up to 2.4.0 are vulnerable to authorization bypass via principal-type confusion, allowing attackers with a valid link-share JWT to manipulate team rosters and bot users.
date: "2026-08-19T14:34:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - authorization-bypass
  - cve-2026-76216
vendors:
  - Vikunja
products:
  - Vikunja (2.4.0 and earlier)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Vikunja through 2.4.0 contains a principal-type confusion vulnerability where LinkSharing principals with id N are treated as user principals with users.id == N at three permission checks lacking type guards.
    confidence_band: high
cves:
  - id: CVE-2026-76216
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76216
  - https://github.com/go-vikunja/vikunja/security/advisories/GHSA-32r8-5843-4qw2
  - https://www.vulncheck.com/advisories/vikunja-through-principal-type-confusion-via-linksharing
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Patch Vikunja instance to 2.4.1 or later to remediate CVE-2026-76216.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies version <= 2.4.0 as affected.
  mitigation_plan:
    - priority: immediate
      action: Monitor API logs for suspicious team/user modification requests.
      owner: Security Team
      addresses: CVE-2026-76216
      evidence: Source notes attacker can remove victims from teams or delete bot users.
---

Vikunja versions through 2.4.0 contain a critical principal-type confusion vulnerability (CVE-2026-76216) stemming from missing type guards in internal permission checks. The vulnerability occurs because the application treats 'LinkSharing' principals with ID N identically to 'user' principals with users.id == N. Because the application uses an autoincrementing ID system, an attacker possessing a valid link-share JWT can exploit ID collisions to bypass authorization boundaries. 

By successfully exploiting this confusion, an unauthorized actor can perform privileged administrative actions, including removing victims from teams, enumerating and deleting bot users, or exfiltrating sensitive team roster information. This vulnerability is classified under CWE-639 (Authorization Bypass Through User-Controlled Key) and represents a significant risk to teams relying on Vikunja for sensitive task and project management. Defenders should prioritize patching to version 2.4.1 or later to implement the missing type guard logic.

## Attack Chain

1. The attacker obtains or generates a valid link-share JWT for a shared Vikunja resource.
2. The attacker identifies the target user's ID or the ID of a target bot user within the application's autoincrement sequence.
3. The attacker crafts a request to the Vikunja API, injecting their link-share JWT.
4. The request hits one of the three vulnerable permission check endpoints lacking type validation.
5. The backend application erroneously maps the attacker's 'LinkSharing' principal ID to the target 'user' principal ID due to the lack of type guards.
6. The application performs authorization logic assuming the attacker is the authenticated user associated with the collided ID.
7. The attacker executes unauthorized operations, such as deleting a bot user or accessing the team roster.
8. The final objective is achieved: unauthorized modification of team configurations or exfiltration of roster data.

## Impact

Successful exploitation allows for unauthorized modification of team structures and data exfiltration. Attackers can specifically remove legitimate team members, delete automation bot users, and access private team rosters. This results in the disruption of project management workflows and potential disclosure of sensitive project data for all organizations utilizing vulnerable versions of Vikunja.

## Recommendation

* Patch all instances of Vikunja to version 2.4.1 or later immediately to address CVE-2026-76216.
* Audit application access logs for unusual patterns of API requests originating from JWT-authenticated sessions that involve administrative endpoints (e.g., team membership or user deletion).
* Review all team rosters for unauthorized modifications or missing bot users that may indicate past exploitation.
* Implement strict rate limiting on API endpoints to mitigate attempts to brute-force or guess sequential user/principal IDs.
