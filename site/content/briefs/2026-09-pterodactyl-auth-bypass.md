---
title: Pterodactyl Panel Authorization Bypass in Scheduled Tasks
slug: 2026-09-pterodactyl-auth-bypass
description: Pterodactyl Panel versions prior to 1.14.1 contain an authorization bypass vulnerability allowing subusers with limited schedule update permissions to execute arbitrary console commands.
date: "2026-09-05T11:32:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pterodactyl:panel:*:*:*:*:*:*:*:*
vendors:
  - Pterodactyl
products:
  - Pterodactyl Panel (< 1.14.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Pterodactyl Panel before 1.14.1 fails to validate action-specific permissions in scheduled task creation, allowing subusers with only schedule.update permission to execute arbitrary console commands.
    confidence_band: high
cves:
  - id: CVE-2026-86177
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86177
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Pterodactyl Panel to 1.14.1 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-86177 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Upgrade Pterodactyl Panel to 1.14.1 or later
      owner: IT Operations
      addresses: CVE-2026-86177
      evidence: NVD vulnerability disclosure
---

Pterodactyl Panel before version 1.14.1 contains an authorization bypass vulnerability identified as CVE-2026-86177. The vulnerability exists within the application's permission validation logic for scheduled tasks. A subuser assigned only the 'schedule.update' permission can craft malicious scheduled task requests that include unauthorized actions, such as executing arbitrary game-server console commands, modifying server power states, or initiating backups. This flaw effectively grants unauthorized subusers elevated control over game server instances, bypassing intended role-based access controls within the panel. Defenders should prioritize patching to version 1.14.1 or later to mitigate the risk of unauthorized server management and command execution by low-privileged accounts.

## Impact

Successful exploitation allows a subuser to execute arbitrary console commands with the privileges of the game server process, leading to potential RCE, unauthorized data access, or denial of service by manipulating power states and backups. This impact is significant for hosting environments managing multi-tenant game server infrastructure.

## Recommendation

* Upgrade all Pterodactyl Panel instances to version 1.14.1 or later immediately.
* Audit existing scheduled tasks within the Pterodactyl Panel to identify any unauthorized or suspicious commands initiated by subusers.
* Review role-based access control (RBAC) configurations to ensure the 'schedule.update' permission is only assigned to trusted users until the patch is applied.
