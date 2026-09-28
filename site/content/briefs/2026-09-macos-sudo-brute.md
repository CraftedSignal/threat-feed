---
title: Excessive Sudo Authentication Failures on macOS
slug: 2026-09-macos-sudo-brute
description: Detection of potential privilege escalation or credential access attempts via repeated sudo authentication failures on macOS hosts.
date: "2026-09-28T10:10:12Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - macos
  - privilege-escalation
  - credential-access
  - security-events
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Repeated sudo authentication failures may indicate an adversary with access to a low-privileged account attempting to guess an administrator password to escalate privileges.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Repeated sudo authentication failures may indicate an adversary with access to a low-privileged account attempting to guess an administrator password to escalate privileges.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/macos/privilege_escalation_excessive_sudo_failures_macos_security_events.toml
  - https://themittenmac.com/detecting-ssh-activity-via-process-monitoring/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the ESQL detection rule for excessive sudo failures to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 4862d004-3f5f-4ce3-9c83-36cdd5dce8c6
  hunt_leads:
    - lead: Search authentication logs for accounts with high volumes of sudo failures not followed by a successful authentication.
      technique_id: T1110.001
      data_needed:
        - logs-macos.authentication-*
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Excessive failed sudo attempts often precede successful brute-force attempts.
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict sudoers file configuration.
      owner: IT Operations
      addresses: T1548.003
      evidence: Limiting sudo access reduces the attack surface for privilege escalation.
---

This threat brief focuses on detecting unauthorized attempts to gain administrative privileges on macOS systems. Attackers who have obtained initial access through a low-privileged account often attempt to escalate privileges by brute-forcing or guessing administrator credentials via the sudo mechanism. macOS logs failed sudo attempts to the unified log, recording information such as the invoking user, the target user, the number of failures, and the requested command. By monitoring the Authentication data stream (logs-macos.authentication-*) provided by the macOS Security Events integration, detection engineers can identify abnormal volumes of failed sudo attempts. A threshold of 10 or more failed attempts within a 9-minute window is a common indicator of automated or manual credential guessing, warranting investigation into the invoking user account and the originating session.

## Impact

Successful exploitation of this activity grants an attacker unauthorized administrative access to the affected macOS host. This enables further malicious actions including credential dumping, persistence establishment, reconnaissance, or malware execution. Targeted systems are typically those exposed to remote access or those with multiple users sharing a single machine.

## Recommendation

- Deploy the provided ESQL detection rule to the SIEM environment to monitor for excessive sudo failures.
- Review authentication logs (logs-macos.authentication-*) when the detection rule triggers to differentiate between malicious intent and legitimate user error.
- Investigate the originating TTY and session type (e.g., local versus SSH) to determine the attacker's point of entry.
- Audit administrative group memberships and restrict sudo access to the minimum number of users required.
