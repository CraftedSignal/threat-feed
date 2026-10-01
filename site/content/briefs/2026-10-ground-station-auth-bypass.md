---
title: Authentication Bypass in Ground-Station via setup.restore
slug: 2026-10-ground-station-auth-bypass
description: Ground-station versions prior to 0.8.0 are susceptible to an authentication bypass vulnerability in the setup.restore command, allowing unauthenticated attackers to execute arbitrary SQL, inject admin users, and achieve full application takeover.
date: "2026-10-01T12:41:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ground-station:ground-station:*:*:*:*:*:*:*:*
vendors:
  - ground-station
products:
  - ground-station (< 0.8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ground-station versions prior to 0.8.0 are vulnerable to an authentication bypass via the setup.restore command when exposed over Socket.IO during initial setup.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An unauthenticated attacker can execute arbitrary SQL commands to inject administrative accounts and forge session tokens, leading to full application takeover.
    confidence_band: high
cves:
  - id: CVE-2026-103244
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103244
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ground-station to 0.8.0 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-103244 fix version
  mitigation_plan:
    - priority: immediate
      action: Disable access to the setup mode or restrict network access to the Socket.IO port if patching is delayed.
      owner: IT Operations
      addresses: CVE-2026-103244
      evidence: Vulnerability allows bypass via setup.restore over Socket.IO
---

Ground-station versions prior to 0.8.0 contain a critical authentication bypass vulnerability (CVE-2026-103244) located within the setup.restore command. This flaw specifically affects the application's first-run setup mode when exposed via Socket.IO. An unauthenticated attacker can leverage this command to execute arbitrary SQL queries against the underlying database. By doing so, they can manually inject administrative user accounts into the system and forge valid session tokens, effectively bypassing all authentication mechanisms. Successful exploitation grants the attacker full administrative access to the application. This vulnerability is particularly dangerous in environments where the setup mode is not restricted or is left accessible post-deployment. Defenders should prioritize updating ground-station to version 0.8.0 or later and ensure that the installation setup process is strictly locked down after initial configuration.

## Attack Chain

1. Attacker identifies a ground-station instance that has not completed its initial configuration or retains access to the setup mode.
2. Attacker initiates a connection to the application's Socket.IO endpoint.
3. Attacker triggers the setup.restore command by sending a specifically crafted request through the socket.
4. The application processes the request, failing to validate the requestor's authentication status.
5. Attacker injects a malicious SQL command payload through the setup.restore parameters.
6. The backend executes the SQL query, inserting a new administrative user record into the database.
7. Attacker uses the injected credentials to generate or forge a valid administrative session token.
8. Attacker authenticates as an administrator, completing the full takeover of the application.

## Impact

Successful exploitation of CVE-2026-103244 results in a complete compromise of the ground-station instance. Attackers gain full administrative control, which allows for the exfiltration of sensitive configuration data, manipulation of application settings, and potential lateral movement within the environment.

## Recommendation

- Upgrade all ground-station instances to version 0.8.0 or later immediately.
- Review network access control lists to ensure the Socket.IO endpoints are not exposed to untrusted networks.
- Inspect audit logs for unauthorized administrative account creation occurring outside of documented maintenance windows.
