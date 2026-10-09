---
title: Detection of Mount Command Execution in Privileged Containers
slug: 2026-10-privileged-container-mount
description: This brief describes a detection mechanism for identifying potential container escapes and host-level privilege escalation via the unauthorized use of the mount utility within privileged containers.
date: "2026-10-09T13:50:27Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - container-security
  - linux
  - privilege-escalation
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: When launched inside a privileged container--a container deployed with all the capabilities of the host machine-- an attacker can access sensitive host level files which could be used for further privilege escalation and container escapes to the host machine.
    confidence_band: high
references:
  - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privileged
  - https://attack.mitre.org/techniques/T1611/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy process-creation detection for mount execution in privileged containers
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific EQL rule for monitoring privileged container behavior.
  hunt_leads:
    - lead: Identify all running containers with privileged security context
      technique_id: T1611
      data_needed:
        - Container runtime configuration logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Privileged containers are the prerequisite for this attack vector.
---

Privileged containers are deployed with extensive capabilities equivalent to the host machine, creating a high-risk environment if an attacker gains code execution. The `mount` utility, when executed within such a context, allows an adversary to attach host file systems to the container's namespace. This capability is frequently abused for container escapes and host-level privilege escalation. Monitoring the execution of `mount` within containers marked with `container.security_context.privileged == true` provides a critical defensive signal against unauthorized host file access. Defenders should establish a baseline for legitimate administrative, backup, and monitoring processes that require mounting operations to minimize noise and improve signal fidelity in containerized production environments.

## Impact

Successful exploitation of this technique permits an attacker to bridge the isolation between the container and the host OS. This can lead to the exfiltration of sensitive configuration files, credentials, or system binaries, ultimately resulting in full host compromise and the potential for lateral movement within the infrastructure.

## Recommendation

- Deploy the provided EQL detection logic to identify `mount` execution within privileged containers.
- Audit all containers currently running with the `privileged` security context and enforce the principle of least privilege by stripping unnecessary capabilities.
- Isolate containers that trigger this alert to prevent potential unauthorized access to host file systems during investigation.
- Implement exception lists in your SIEM/detection platform for known, legitimate maintenance or monitoring tasks that perform valid mounting operations.
