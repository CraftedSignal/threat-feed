---
title: Local Privilege Escalation in Palo Alto Networks GlobalProtect
slug: 2026-08-globalprotect-lpe
description: A local privilege escalation vulnerability (CVE-2026-0299) in the Palo Alto Networks GlobalProtect app allows authenticated local users to escalate to SYSTEM or root privileges via untrusted search path exploitation.
date: "2026-08-12T16:48:11Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - privilege-escalation
  - vulnerability
  - endpoint-security
vendors:
  - Palo Alto Networks
products:
  - GlobalProtect App 6.3
  - GlobalProtect App 6.2
  - GlobalProtect App 6.0
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Local privilege escalation vulnerabilities in the Palo Alto Networks GlobalProtect™ app enable a local user to escalate their privileges to NT AUTHORITY\SYSTEM on Windows, and root on macOS and Linux.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0299
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade GlobalProtect agents to patched versions
      owner: IT Operations
      due: 72h
      evidence: Vendor provided patches in CVE-2026-0299
  hunt_leads:
    - lead: Monitor for anomalous process creation chains originating from GlobalProtect service
      technique_id: T1068
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary command execution
---

Palo Alto Networks has disclosed a local privilege escalation (LPE) vulnerability, identified as CVE-2026-0299, affecting the GlobalProtect application across Windows, macOS, and Linux platforms. The vulnerability is rooted in an untrusted search path issue (CWE-426), which permits a low-privileged local user to manipulate the environment or file system in a way that causes the application to execute arbitrary code with elevated privileges - NT AUTHORITY\SYSTEM on Windows and root on macOS and Linux.

This vulnerability is significant for organizations relying on GlobalProtect for secure access, as it enables lateral movement and persistence if an attacker has already gained initial low-privileged access to an endpoint. Palo Alto Networks reports that the vulnerability was discovered internally and there is currently no evidence of malicious exploitation in the wild. Affected versions include various branches of 6.0, 6.2, and 6.3. Defenders should prioritize patching, as no workarounds are available to mitigate the underlying search path issue.

## Impact

Successful exploitation of CVE-2026-0299 allows a local user, regardless of their original privilege level, to gain full control over the affected system. This facilitates the bypass of security controls, unauthorized access to sensitive data stored on the endpoint, and the potential for persistent backdoors to be installed at the OS kernel or system level. Given the broad deployment of GlobalProtect in enterprise environments, the potential blast radius for an attacker with local access is high.

## Recommendation

Prioritize the deployment of patches provided by Palo Alto Networks across the enterprise fleet.
* Update all GlobalProtect Windows and macOS instances to at least 6.3.3-h14 or 6.2.8-h13.
* For GlobalProtect version 6.0, update all instances to version 6.0.15 or later.
* Audit endpoint security logs for unexpected child processes spawned by GlobalProtect binaries, which may indicate testing or exploitation of the service path.
