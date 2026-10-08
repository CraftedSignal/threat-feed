---
title: Abuse of Windows Secondary Logon Service for Privilege Escalation
slug: 2026-10-secondary-logon-abuse
description: Adversaries may perform local privilege escalation by abusing the Windows Secondary Logon service to spawn processes with alternate user credentials.
date: "2026-10-08T19:07:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - windows
  - secondary-logon
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: Adversaries may create a new process with a different token to escalate privileges and bypass access controls.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: The rule description references token manipulation techniques used to escalate privileges.
    confidence_band: high
rules:
  - title: Detect Process Creation via Secondary Logon
    description: Detects process creation events that follow a successful authentication via the Windows Secondary Logon service using TargetLogonId correlation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1134.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Audit Logon and Audit Process Creation on Windows endpoints
      owner: IT Operations
      due: 72h
      evidence: Setup requirements for the detection rule
  hunt_leads:
    - lead: Search for instances of seclogon activity followed by suspicious process execution
      technique_id: T1134.002
      data_needed:
        - Windows Event Logs 4624 and 4688
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Investigation guide suggests checking for unusual processes created via Secondary Logon
---

The Windows Secondary Logon service (seclogon) is designed to allow users to execute processes under alternate credentials, a feature frequently leveraged for legitimate administrative tasks. However, this functionality can be abused by adversaries to achieve local privilege escalation. By invoking the service to create a process with an alternate security token, an attacker can bypass access controls and execute code with higher privileges than their current session.

This technique is often used as a post-exploitation mechanism to transition from a low-privileged account to a high-privileged one. Defenders should monitor for successful authentication events linked to the Secondary Logon service, specifically looking for process creation activities associated with the resulting TargetLogonId. This pattern is indicative of potential privilege escalation attempts when observed in conjunction with unexpected process execution.

## Attack Chain

1. Attacker gains initial access to the system through a low-privileged account.
2. Attacker prepares malicious payloads or tools to be executed under a target privileged context.
3. Attacker invokes the Secondary Logon service (seclogon) using the RunAs API or equivalent command-line tools.
4. The system triggers a local authentication event where the svchost.exe process handles the request via seclogon.
5. The service validates the alternate credentials and generates a new, unique Logon ID for the session.
6. The adversary launches a new process (e.g., cmd.exe, powershell.exe) linked to this new TargetLogonId.
7. The process executes with the elevated or alternate user security context, effectively completing the privilege escalation.

## Impact

Successful exploitation allows an adversary to execute arbitrary code with elevated privileges, potentially leading to full system compromise, exfiltration of sensitive data, or persistence establishment. This impact is significant in environments where administrative credentials can be harvested or abused via this service.

## Recommendation

- Enable 'Audit Logon' and 'Audit Process Creation' policies on all Windows endpoints to capture the necessary telemetry.
- Deploy the provided Sigma rule to detect the sequence of Secondary Logon authentication followed by process creation.
- Review and baseline administrative tasks that legitimately utilize the Secondary Logon service to reduce false positives.
- Investigate any process creation events linked to 'seclogo*' logon processes that originate from unexpected parent processes.
