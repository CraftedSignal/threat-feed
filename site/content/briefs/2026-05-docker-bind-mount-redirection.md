---
title: Docker Race Condition Allows Bind Mount Redirection to Host Path (CVE-2026-42306)
slug: 2026-05-docker-bind-mount-redirection
description: A race condition in Docker's `docker cp` command allows a malicious container to redirect a bind mount target to an arbitrary host path by manipulating symlinks during the setup of temporary filesystem views, potentially overwriting host files or causing denial of service.
date: "2026-05-18T17:54:09Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - privilege-escalation
  - defense-evasion
  - docker
vendors:
  - Docker
  - Moby
products:
  - docker/docker (<= 28.5.2)
  - moby/moby/v2 (< 2.0.0-beta.14)
  - moby/moby (<= 28.5.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-rg2x-37c3-w2rh
  - CVE-2026-42306
rules:
  - title: Detect Docker cp to potentially malicious containers
    description: Detects docker cp commands executed to containers with mounted volumes which could indicate a potential exploitation of CVE-2026-42306.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect archive API access to containers
    description: Detects access to the Docker archive API endpoints (PUT/HEAD /containers/{id}/archive) which could be abused in CVE-2026-42306 exploitation.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

A race condition vulnerability exists in Docker's `docker cp` command related to the setup of temporary filesystem views when copying files into a container. This flaw, identified as CVE-2026-42306, allows a malicious container to redirect a bind mount target to an arbitrary host path. The vulnerability occurs because, during the setup, a process inside the container can replace the mount destination with a symlink pointing to the host before the mount syscall completes. This can lead to overwriting host files with the volume's contents or causing denial of service by masking the host path. This vulnerability affects `docker/docker` versions up to 28.5.2 and `moby/moby` versions up to 28.5.2 and versions of `moby/moby/v2` prior to 2.0.0-beta.14.

## Attack Chain

1. A container with at least one volume mount is created.
2. A malicious process within the container gains the ability to rapidly create and swap symlinks at the volume mount destination path.
3. The attacker identifies a target host path for redirection.
4. The attacker prepares malicious content to overwrite the host path.
5. An operator initiates a `docker cp` command to copy files into the container.
6. Before the `mount()` syscall completes, the malicious process replaces the mount destination with a symlink pointing to the attacker-controlled host path.
7. The `mount()` syscall follows the symlink, and the volume is bind-mounted to the attacker-controlled host path.
8. Depending on the volume content and permissions, either the host files are overwritten, or the host path is masked, potentially leading to denial of service.

## Impact

Successful exploitation of this race condition (CVE-2026-42306) allows a malicious container to redirect a volume bind mount to an arbitrary host path. If the volume is writable, arbitrary host files at the redirected path could be overwritten, leading to data corruption or system compromise. If the volume is read-only, the host path is masked by the mount, causing a denial of service. While the mount is temporary and torn down after the `docker cp` completes, the effects of any writes persist.

## Recommendation

*   Upgrade to patched versions of `go/github.com/docker/docker` and `go/github.com/moby/moby` to address CVE-2026-42306.
*   Only run containers from trusted images to minimize the risk of malicious processes exploiting the vulnerability.
*   Avoid using `docker cp` with untrusted running containers to prevent unintended bind mount redirection.
*   Implement authorization plugins to restrict access to the archive API endpoints (`PUT /containers/{id}/archive`, `HEAD /containers/{id}/archive`) as a workaround.
