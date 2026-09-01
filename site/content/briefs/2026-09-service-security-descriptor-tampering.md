---
title: Service Security Descriptor Tampering via Sc.exe
slug: 2026-09-service-security-descriptor-tampering
description: Adversaries use the sc.exe utility to modify service security descriptors to achieve persistence, escalate privileges, or hide malicious services from standard management tools.
date: "2026-09-01T12:24:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - stealth
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Adversaries often target Windows Service security descriptors to maintain persistence.
    confidence_band: high
references:
  - https://blog.talosintelligence.com/2021/10/threat-hunting-in-large-datasets-by.html
  - https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
rules:
  - title: Detect Service Security Descriptor Tampering via Sc.exe
    description: Detects the use of the sc.exe utility to modify service security descriptors via the sdset command, which can be used to hide services or restrict access.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1574.011
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
    - action: Deploy Sigma detection rule for sc.exe sdset
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in source.
  hunt_leads:
    - lead: Search for historical use of sc.exe sdset in EDR/process logs
      technique_id: T1574.011
      data_needed:
        - process_creation
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source highlights sdset as a technique for stealth.
---

Adversaries often target Windows Service security descriptors to maintain persistence and evade detection. By using the built-in 'sc.exe' utility, an attacker can invoke the 'sdset' command to modify the Security Descriptor Definition Language (SDDL) string associated with a specific service. This technique allows an attacker to deny access to security administrators, restrict the ability of monitoring tools to query the service status, or hide the service from standard administrative interfaces. This modification requires elevated privileges, typically SYSTEM or local Administrator, but provides a high level of stealth once established. Defenders should monitor for the usage of 'sc.exe' coupled with 'sdset' as it is rarely used in legitimate administrative workflows for service hardening.

## Attack Chain

1. The attacker gains initial access and executes a payload with administrative or SYSTEM privileges.
2. The attacker identifies a target service or installs a new malicious service using 'sc.exe create'.
3. The attacker determines the required SDDL string to achieve their desired permission mask (e.g., denying 'Read' or 'Write' access to the SYSTEM account).
4. The attacker executes 'sc.exe &lt;service_name> sdset &lt;sddl_string>' via command line or a script.
5. The Windows Service Control Manager updates the security descriptor in the registry under 'HKLM\SYSTEM\CurrentControlSet\Services\&lt;service_name>\Security'.
6. Administrative tools or security products attempting to query the service state receive an 'Access Denied' error or fail to display the service.
7. The malicious service continues to operate in the background, undetected by standard monitoring workflows.

## Impact

Successful tampering with service security descriptors can lead to long-term persistence that is invisible to standard administrative management tools. In environments where security teams rely on service listing and status monitoring to detect anomalies, this technique facilitates stealthy command-and-control communication or data collection, increasing the difficulty of incident response and forensic analysis.

## Recommendation

1. Deploy the provided Sigma rule to detect the use of 'sc.exe' with the 'sdset' parameter across all Windows endpoints.
2. Baseline legitimate service configuration activities in your environment to identify authorized automation tools that might modify service permissions.
3. Audit the 'Security' registry keys for critical services to ensure descriptors match the organization's gold-standard configuration.
4. Enable Sysmon or Windows Event Log (EID 4688) to ensure command-line auditing is available for 'sc.exe'.
