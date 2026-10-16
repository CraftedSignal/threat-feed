---
title: Authorization Bypass in HestiaCP
slug: 2026-10-hestiacp-auth-bypass
description: HestiaCP versions prior to 1.10.5 contain an authorization bypass vulnerability allowing non-privileged administrators to impersonate the ROOT_USER and execute arbitrary cron tasks.
date: "2026-10-16T18:47:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hestiacp:hestiacp:*:*:*:*:*:*:*:*
vendors:
  - HestiaCP
products:
  - HestiaCP (< 1.10.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: HestiaCP before 1.10.5 contains an authorization bypass vulnerability that allows non-ROOT_USER administrators to perform write actions while impersonating the protected ROOT_USER account.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Attackers can log in via the loginas parameter and POST to /add/cron/, because the read-only flag is never checked.
    confidence_band: high
cves:
  - id: CVE-2026-111627
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111627
rules:
  - title: Detect HestiaCP Authorization Bypass Attempt
    description: Detects exploitation attempts against CVE-2026-111627 by monitoring POST requests to /add/cron/ with the loginas parameter.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
      - T1548
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade HestiaCP to version 1.10.5 or later.
      owner: IT Operations
      due: 24h
      evidence: Source states HestiaCP before 1.10.5 is vulnerable.
  hunt_leads:
    - lead: Search web logs for POST requests to /add/cron/ containing loginas.
      technique_id: T1068
      data_needed:
        - webserver_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this specific path and parameter as the exploitation vector.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.10.5.
      owner: IT Operations
      addresses: CVE-2026-111627
      evidence: NVD advisory
---

HestiaCP versions before 1.10.5 are affected by an authorization bypass vulnerability that enables non-ROOT_USER administrators to perform write operations by impersonating the system's protected ROOT_USER account. The vulnerability stems from a flaw in the application's permission logic where the read-only flag is improperly validated when using the 'loginas' parameter. An attacker with administrative access to a sub-account can exploit this by sending a crafted POST request to the '/add/cron/' endpoint. This action causes the underlying 'crond' service to execute the requested commands with the privileges associated with the protected administrative system account, potentially leading to full system compromise. Defenders should prioritize updating to version 1.10.5 or later to remediate this flaw.

## Attack Chain

1. Attacker gains access to a low-privilege administrator sub-account within the HestiaCP control panel.
2. Attacker crafts a request utilizing the 'loginas' parameter to assume the context of the ROOT_USER.
3. Attacker targets the '/add/cron/' API endpoint to initiate a task creation request.
4. The application fails to validate the read-only restriction for the session context.
5. The unauthorized write operation is processed, and the cron job is persisted to the system configuration.
6. The 'crond' daemon schedules the task based on the malicious input.
7. The system executes the arbitrary command with ROOT_USER privileges.

## Impact

Successful exploitation allows a restricted administrator to elevate their privileges to the ROOT_USER level and execute arbitrary system commands. This impacts the confidentiality, integrity, and availability of the hosting server, potentially affecting all hosted websites and databases managed by the HestiaCP instance.

## Recommendation

* Patch all HestiaCP instances to version 1.10.5 or later immediately.
* Audit web server logs for suspicious POST requests to the '/add/cron/' endpoint originating from non-root administrative accounts.
* Review all scheduled cron jobs on HestiaCP servers for unauthorized or unexpected entries created by sub-administrators.
