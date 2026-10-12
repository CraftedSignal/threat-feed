---
title: Detection of Service Termination via Linux Auditd
slug: 2026-10-linux-auditd-service-stop
description: Adversaries leverage service termination techniques on Linux systems to disable security controls and disrupt operations, as documented in the Industroyer2 malware campaign.
date: "2026-10-12T17:49:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - auditd
  - defensive-evasion
  - impact
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
    evidence: The following analytic detects attempts to stop a service on Linux systems.
    confidence_band: high
references:
  - https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/
  - https://cert.gov.ua/article/39518
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1489/T1489.yaml#L63
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy hunting logic to monitor Auditd SERVICE_STOP events.
      owner: Detection Engineering
      due: 72h
      evidence: Analytic provided by Splunk security_content.
  hunt_leads:
    - lead: Auditd SERVICE_STOP events linked to non-standard parent processes.
      technique_id: T1489
      data_needed:
        - Auditd logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Analytic detects attempts to stop a service on Linux systems.
---

Adversaries often target critical system services on Linux platforms to disable defensive mechanisms, facilitate privilege escalation, or prepare for destructive operations. The monitoring of the Linux Auditd `SERVICE_STOP` event type provides visibility into these attempts. This activity was explicitly noted in campaigns involving malware like Industroyer2 and AwfulShred, where attackers sought to neutralize host-based security controls before deploying payloads. Defending against this behavior is critical for maintaining system integrity and operational availability. Detection engineering teams should baseline legitimate administrative service management activity to reduce noise, as service control is a frequent task for system administrators and automation scripts.

## Impact

Successful termination of security or operational services can lead to total loss of host visibility, bypass of endpoint detection and response (EDR) agents, privilege escalation, and the subsequent deployment of destructive payloads. This technique has been observed in high-impact campaigns targeting critical infrastructure, aiming to disable services that monitor system health or log security-relevant events.

## Recommendation

* Ingest Auditd logs (specifically `SYSCALL`, `TYPE`, `EXECVE`, and `PROCTITLE` events) into your SIEM and ensure they are parsed according to the Common Information Model (CIM).
* Deploy detection logic targeting Auditd `SERVICE_STOP` events, particularly those initiated by non-administrative user contexts.
* Baseline the `comm` and `exe` fields associated with service management in your environment to distinguish between legitimate operator activity and potential adversary activity.
* Monitor for service termination events originating from unexpected processes, specifically those not associated with systemd or recognized administration tools.
