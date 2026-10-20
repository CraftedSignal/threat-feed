---
brief_id: brief-2026-10-20-kiro-crew-auth-bypass
event_id: brief-2026-10-20-kiro-crew-auth-bypass
revision: 1
activity_at: "2026-10-20T21:54:09Z"
title: 'Kiro Crew: Missing authorization in WhatsApp group channel (CVE-2026-112380)'
slug: 2026-10-kiro-crew-auth-bypass
description: A missing authorization vulnerability in the Kiro Crew WhatsApp integration allows remote attackers who are group members to hijack agent sessions and execute arbitrary commands on the host system.
date: "2026-10-20T21:54:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:kiro:kiro_crew:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - authentication-bypass
vendors:
  - Kiro
products:
  - Kiro Crew (< 0.7.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Missing authorization in the WhatsApp group channel in Kiro Crew might allow a remote actor... to control the operator's other agent sessions and execute arbitrary commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: '...execute arbitrary commands on the host running Kiro Crew via messages sent to the group.'
    confidence_band: high
cves:
  - id: CVE-2026-112380
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112380
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Kiro Crew to version 0.7.2 or later
      owner: IT Operations
      due: 24h
      evidence: To remediate this issue, users should upgrade to version 0.7.2.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Kiro Crew to version 0.7.2
      owner: IT Operations
      addresses: CVE-2026-112380
      evidence: Source recommends upgrading to version 0.7.2
---

Kiro Crew contains a critical missing authorization vulnerability (CVE-2026-112380) within its WhatsApp group channel integration. An attacker who is already a participant in an operator-configured WhatsApp group can leverage this flaw to send specifically crafted messages that the Kiro Crew application processes without proper authorization checks. This enables the remote attacker to hijack other agent sessions managed by the software and execute arbitrary commands on the underlying host operating system. This vulnerability poses a severe risk, as it allows for full command execution and session control from within an existing communication channel. Organizations utilizing Kiro Crew are advised to update to version 0.7.2 or later immediately to mitigate this exposure.

## Attack Chain

1. The operator configures a WhatsApp group channel for Kiro Crew agent communication.
2. The attacker gains membership into the operator-configured WhatsApp group.
3. The attacker identifies the command-parsing logic within the Kiro Crew WhatsApp integration.
4. The attacker crafts a malicious message containing command sequences or session control instructions.
5. The attacker sends the crafted message to the WhatsApp group.
6. The Kiro Crew application parses the message from the group channel.
7. The application fails to perform authorization validation on the message sender or the command content.
8. The host system executes the arbitrary commands or performs session hijacking actions as authorized by the Kiro Crew process.

## Impact

Successful exploitation of CVE-2026-112380 results in unauthorized command execution on the host machine and complete takeover of active agent sessions. This effectively grants an attacker full control over the Kiro Crew environment and potentially the underlying host, allowing for data exfiltration, lateral movement, and further persistent access.

## Recommendation

1. Upgrade Kiro Crew to version 0.7.2 or later across all instances immediately to patch CVE-2026-112380.
2. Audit current WhatsApp group memberships configured within Kiro Crew to ensure only authorized entities have access to the communication channels monitored by the software.
3. Review audit logs for any unexpected command executions or session handovers originating from the WhatsApp integration module.
