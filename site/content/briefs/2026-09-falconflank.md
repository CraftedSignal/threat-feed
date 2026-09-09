---
title: CrowdStrike Falcon Sensor Local Privilege Escalation (FalconFlank)
slug: 2026-09-falconflank
description: A local privilege escalation vulnerability known as FalconFlank exists in the CrowdStrike Falcon Sensor Windows agent due to a TOCTOU race condition in the Office macro remediation workflow.
date: "2026-09-09T18:47:52Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - privilege-escalation
  - endpoint-security
  - windows
vendors:
  - CrowdStrike
products:
  - Falcon Sensor
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The attack leverages a time-of-check to time-of-use (TOCTOU) race condition, allowing an attacker with code execution on a vulnerable system to hijack the Office malicious macro remediation workflow.
    confidence_band: high
references:
  - https://arcticwolf.com/resources/blog/crowdstrike-falcon-sensor-local-privilege-escalation-zero-day-falconflank/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review security sensor update cycles and monitor vendor communications for a patch.
      owner: IT Operations
      due: 24h
      evidence: Source disclosure of a zero-day vulnerability in Falcon Sensor.
  hunt_leads:
    - lead: Identify suspicious child processes created by CrowdStrike remediation workflows.
      technique_id: T1068
      data_needed:
        - Process creation logs
      priority: medium
      confidence: moderate
      disposition: hunt_now
      evidence: The flaw involves hijacking the Office malicious macro remediation workflow.
---

Security researcher Nightmare Eclipse/Chaotic Eclipse has disclosed a zero-day vulnerability, identified as 'FalconFlank', affecting the CrowdStrike Falcon Sensor on Windows systems. The flaw resides within the product's remediation workflow for malicious Office macros. By exploiting a time-of-check to time-of-use (TOCTOU) race condition during this automated remediation process, an attacker who has already obtained low-privileged code execution on the host can escalate their privileges to those of the security sensor. This vulnerability is significant because it provides a path for an attacker to gain elevated system rights by manipulating the very security software intended to protect the endpoint. Defenders should review security sensor logs for unexpected file access patterns or suspicious process creation events initiated by the Falcon sensor remediation components.

## Impact

Successful exploitation of FalconFlank allows a low-privileged attacker to escalate to higher-privileged execution, potentially enabling full system compromise. The vulnerability affects organizations relying on CrowdStrike Falcon Sensor for endpoint protection on Windows platforms. If leveraged, an attacker could disable security controls, exfiltrate sensitive data, or establish persistence with elevated privileges.

## Recommendation

- Monitor the CrowdStrike official support portal for security updates and patch the Falcon Sensor agent as soon as a fix is made available.
- Audit endpoint process creation logs for unexpected child processes spawned by Falcon sensor remediation binaries or services.
- Review file integrity logs for frequent, rapid modifications to temporary file locations or Office macro caches that might indicate exploitation of the TOCTOU race condition.
