---
title: Detection of Host Root Directory Mounts in Docker Containers
slug: 2026-10-linux-docker-root-mount
description: Attackers can achieve container escape and escalate privileges on Linux hosts by mounting the entire host filesystem into a container with elevated privileges.
date: "2026-10-12T17:50:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container-escape
  - privilege-escalation
  - docker
  - linux
vendors:
  - Docker
products:
  - Docker Engine
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: Mounting the entire host root directory into a container effectively grants the container visibility and potential write access to all files on the host system.
    confidence_band: high
references:
  - https://docs.docker.com/engine/storage/volumes/
  - https://gtfobins.github.io/gtfobins/docker/
rules:
  - title: Detect Docker Root Directory Mount
    description: Detects Docker containers launched with a volume mount mapping the host root directory, a potential indicator of container escape
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM to flag container root directory mounts
      owner: Detection Engineering
      due: 48h
      evidence: This detection identifies Docker containers that mount the host's root directory into the container filesystem.
  hunt_leads:
    - lead: Search historic process creation logs for the pattern '-v /:/'
      technique_id: T1611
      data_needed:
        - Process creation events with command line
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This detection identifies Docker containers that mount the host's root directory into the container filesystem.
---

This threat involves the exploitation of misconfigured Docker containers to facilitate container escape and privilege escalation on Linux hosts. By mounting the host's root directory (`/`) into a container using the `-v` or `--volume` flag with a syntax such as `-v /:/host`, an attacker gains full read/write access to the underlying host filesystem. This configuration is particularly dangerous when the container is executed with `--privileged` flags or by a user with root-level access. Defenders should monitor for Docker process execution command lines that include volume mapping arguments targeting the root directory, as this is a primary technique used by threat actors to break out of containerized environments and achieve persistence or exfiltration on the host.

## Attack Chain

1. Attacker gains initial access to a Linux host where Docker is running.
2. Attacker enumerates available container images or existing running containers.
3. Attacker initiates a new container or modifies an existing one to include a volume mount parameter.
4. The container is launched with the argument `-v /:/host` or similar to map the host root directory.
5. The attacker enters the container shell, now having access to the host's `/etc/shadow`, SSH keys, or binaries.
6. Attacker modifies host-level system files (e.g., `/etc/crontab` or `.ssh/authorized_keys`) to gain persistent access.
7. Attacker executes commands from within the container that affect the host filesystem to escalate privileges to root.

## Impact

Successful exploitation allows an attacker to move from a containerized environment to the host system. This can lead to full system compromise, data theft, or the deployment of persistent backdoors on the host. This technique is often observed in the post-exploitation phase of cloud-native environment attacks, specifically targeting misconfigured infrastructure-as-a-service or CI/CD pipelines.

## Recommendation

* Deploy the Sigma rule below to detect instances of Docker containers mounting the host root directory.
* Audit all Docker-related process creation events via EDR/Sysmon telemetry for unauthorized volume mounting.
* Enforce restrictive security policies on container runtimes to prevent the use of `--privileged` mode or broad volume mounts.
