---
brief_id: brief-2026-10-21-windows-firewall-deletion
event_id: brief-2026-10-21-windows-firewall-deletion
revision: 1
activity_at: "2026-10-21T00:48:09Z"
title: Windows Firewall Exception List Rule Deletion
slug: 2026-10-windows-firewall-deletion
description: Adversaries may delete Windows Firewall rules to impair security controls and facilitate unauthorized network communication.
date: "2026-10-21T00:48:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - defense-impairment
  - windows
  - firewall
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/firewall_as/win_firewall_as_delete_rule.yml
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)
rules:
  - title: Detect Firewall Rule Deletion
    description: Detects when a rule has been deleted from the Windows Defender Firewall exception list by non-system processes
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - firewall
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to identify unauthorized firewall rule deletions
      owner: Detection Engineering
      due: 72h
      evidence: Sigma rule provided in brief
  hunt_leads:
    - lead: Search for historical Event ID 2006 or 2052 occurrences to identify past unauthorized changes
      technique_id: T1686.003
      data_needed:
        - Event log
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source documentation of firewall rule deletion events
---

The deletion of Windows Firewall rules is a common technique used by threat actors to perform defense impairment. By removing existing rules, attackers can disable inbound or outbound traffic filtering that would otherwise block their command and control (C2) communication or lateral movement activities. This behavior can be identified by monitoring Windows Defender Firewall events for rule deletion triggers, specifically Event IDs 2006 and 2052. Defenders should focus on rule modifications initiated by processes not associated with trusted system services or legitimate administrative installation processes.

## Attack Chain

1. An attacker gains elevated execution privileges on a target Windows host.
2. The attacker identifies restrictive firewall rules that impede their desired network traffic.
3. The attacker executes a command or script using tools like netsh.exe or PowerShell to modify the firewall configuration.
4. The attacker deletes the target firewall rule from the Windows Defender Firewall exception list.
5. The Windows security event log captures the modification (Event IDs 2006 or 2052).
6. The firewall becomes permissive for the previously blocked traffic.
7. The attacker establishes unauthorized network connections to an external C2 server or internal target.

## Impact

Successful defense impairment through firewall rule deletion leaves systems exposed to unauthorized inbound access and allows malicious outbound traffic that would otherwise be blocked. This activity is typically a precursor to data exfiltration, payload delivery, or lateral movement within the network.

## Recommendation

- Deploy the provided Sigma rule to detect suspicious deletion of firewall rules by unauthorized processes.
- Baseline legitimate software installers and administrative tasks that modify the firewall to tune out false positives.
- Review Event ID 2006 and 2052 logs regularly to identify non-standard firewall modifications.
