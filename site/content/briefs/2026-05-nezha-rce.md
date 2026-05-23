---
title: Nezha Monitoring Cross-Tenant RCE via Cron Task Injection
slug: 2026-05-nezha-rce
description: A RoleMember in Nezha monitoring dashboard can achieve cross-tenant remote code execution by injecting arbitrary commands into cron tasks due to insufficient authorization checks, impacting all monitored hosts in the deployment.
date: "2026-05-23T00:19:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - privilege-escalation
  - cron
  - authorization
  - nezha
vendors:
  - Nezha
products:
  - nezha
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://github.com/advisories/GHSA-99gv-2m7h-3hh9
rules:
  - title: Detect Nezha Cron Task Creation with Empty Server List
    description: Detects the creation of a Nezha cron task with an empty server list and CoverAll setting, indicating a potential cross-tenant RCE attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1053.005
    data_sources:
      - webserver
  - title: Detect Unauthorized Cron Task Execution via Webhook
    description: Detects a Nezha CronTask execution where output data is being sent to a webhook, potentially indicating exfiltration by an unauthorized user.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - webserver
  - title: Detect Nezha API Login from Unusual Source IP
    description: Detects initial login to the Nezha dashboard API from a previously unseen source IP address, potentially indicating account compromise or unauthorized access attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
rules_count: 3
---

The Nezha monitoring dashboard is vulnerable to a cross-tenant RCE. A `RoleMember` (Role==1), even one self-registered via OAuth2, can exploit insufficient authorization checks in the cron task creation process (`POST /api/v1/cron` and `PATCH /api/v1/cron/:id`). The vulnerability stems from the cron routes being handled by `commonHandler` instead of `adminHandler`, and a vacuous-true bypass in the permission check for cron creation. By creating a scheduled cron task with `Cover=CronCoverAll, Servers=[]` and an arbitrary `Command`, the attacker can execute commands on every server in the global `ServerShared` map, which includes servers belonging to other tenants. This allows any `RoleMember` to gain pre-validated RCE on every Nezha-monitored host in the deployment. Affected versions include commit `50dc8e660326b9f22990898142c58b7a5312b42a` and earlier on the `master` branch.

## Attack Chain

1. Attacker gains `RoleMember` access to the Nezha dashboard, either through admin-granted credentials or self-registration via OAuth2 if enabled.
2. Attacker obtains a JWT token by authenticating against the `/api/v1/login` endpoint using their `RoleMember` credentials.
3. Attacker creates a webhook notification via `POST /api/v1/notification` pointing to an attacker-controlled server (e.g., `https://attacker.example.com/exfil`).
4. Attacker creates a notification group via `POST /api/v1/notification-group` and associates the newly created webhook notification with this group.
5. Attacker crafts a malicious cron task payload using `POST /api/v1/cron` with `servers: []`, `cover: 1`, `push_successful: true`, and an arbitrary command (e.g., `id; hostname; cat /etc/shadow`) to be executed on all monitored servers. The `notification_group_id` field is set to the ID of the attacker's notification group.
6. The cron task is scheduled and, upon execution, the crafted command is sent to all monitored Nezha agents.
7. Each agent executes the command and sends the output back to the Nezha dashboard.
8. The Nezha dashboard, due to the `push_successful: true` setting, pushes the command output to the attacker-controlled webhook, allowing the attacker to collect sensitive information from all monitored hosts.

## Impact

Successful exploitation allows any `RoleMember` to achieve cross-tenant RCE on every host monitored by the Nezha dashboard. This can lead to full compromise of all monitored systems, including data exfiltration, privilege escalation, and disruption of services. The vulnerability affects all deployments where `RoleMember` accounts are enabled, including those with OAuth2 self-registration. The impact is especially severe as the Nezha agent typically runs as root.

## Recommendation

*   Immediately switch `/cron` write operations to `adminHandler` to restrict cron task creation and modification to administrators, mitigating unauthorized command injection (reference: `cmd/dashboard/controller/controller.go:131-135`).
*   Implement a per-server permission gate in the `CronTrigger` function to ensure that cron tasks are only executed on servers owned by the user or an administrator. This adds an additional layer of security (reference: `service/singleton/crontask.go:133-181`).
*   Reject cron task creation with empty `Servers` lists when `Cover=CronCoverAll` to prevent unrestricted command execution across all hosts (reference: `cmd/dashboard/controller/cron.go:45-85`).
