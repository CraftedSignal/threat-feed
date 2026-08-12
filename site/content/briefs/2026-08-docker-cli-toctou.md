---
title: 'CVE-2026-17106: TOCTOU Race Condition in Docker CLI'
slug: 2026-08-docker-cli-toctou
description: A TOCTOU race condition in Docker CLI versions 29.6.1 and earlier allows malicious containers to perform arbitrary file writes on the host filesystem via the 'docker cp' command.
date: "2026-08-12T18:23:48Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - 686f6c61
vendors:
  - Docker
products:
  - Docker CLI (<= 29.6.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Privilege Escalation Vulnerability
    evidence: The variant Linux overwrites /usr/bin/runc and achieves code execution as root on the host at the next docker run / exec.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574.006
    technique_name: 'Hijack Execution Flow: DLL Side-Loading'
    evidence: Camouflage a real directory /watched/file.txt/ as a regular file ... via an LD_PRELOAD library that intercepts open, openat.
    confidence_band: high
references:
  - https://sploitus.com/exploit?id=25FB4F14-D5EF-52FA-A282-EDDD3ACBC28B
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Docker CLI to 29.7.0 across all host and CI environments
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-17106 is patched starting from 29.7.0.
  mitigation_plan:
    - priority: immediate
      action: Avoid executing 'docker cp' from untrusted or unverified container images
      owner: Security Engineering
      addresses: CVE-2026-17106
      evidence: The bug resides in the CLI extraction of the tarball produced during docker cp.
---

CVE-2026-17106 is a Time-of-Check Time-of-Use (TOCTOU) race condition vulnerability located in the tar extraction logic of the Docker CLI (version 29.6.1 and earlier). The flaw is specific to the client-side CLI tool and is triggered during the execution of 'docker cp' from a container. An attacker can manipulate file access patterns within a compromised container to win a race condition against the Docker daemon. By replacing a directory with an absolute symlink while the tar file is being processed, an attacker can force the Docker CLI to extract subsequent files outside of the intended destination directory, effectively granting arbitrary write access to the host filesystem. On Linux hosts, this can be weaponized to overwrite binaries such as '/usr/bin/runc', leading to full command execution with root privileges on the host during subsequent container lifecycle events. This vulnerability was addressed in Docker CLI 29.7.0.

## Attack Chain

1. Attacker deploys a malicious container using a library (e.g., LD_PRELOAD) to intercept system calls and mask a directory as a regular file.
2. The malicious container creates a large 'decoy' file (e.g., 16 MiB) to force the Docker daemon to take significant time during tar production.
3. The attacker monitors 'docker cp' access patterns using 'inotify' within the container to detect when the daemon initiates the file read process.
4. Upon detecting the daemon access, the attacker executes an atomic 'rename(2)' operation to replace the 'escape/' directory with an absolute symlink pointing to a sensitive location on the host (e.g., /usr/bin).
5. The daemon completes the tar production, now including the attacker's symlink and subsequent payload files.
6. The vulnerable Docker CLI client processes the tar file, creating the symlink on the host filesystem at the specified destination.
7. The Docker CLI continues extracting files through the newly created symlink, writing the payload into the target host directory.
8. The attacker achieves arbitrary file write, or specifically overwrites '/usr/bin/runc' to gain host-level code execution as root.

## Impact

Successful exploitation allows a containerized process to escape its isolation and write arbitrary files to the host filesystem with the permissions of the user executing the 'docker cp' command. In high-privilege scenarios, such as when the Docker CLI is run by a root user, this vulnerability enables complete host system compromise, including the ability to overwrite critical system binaries like 'runc'.

## Recommendation

* Update the Docker CLI on all development, CI/CD, and administrator workstations to version 29.7.0 or later immediately.
* Audit administrative workflows that utilize 'docker cp' to interact with untrusted or externally sourced container images.
* Restrict container execution privileges using security profiles (e.g., AppArmor, Seccomp) to limit the ability of containers to interact with internal Docker socket or CLI-related files.
* Monitor file integrity on critical host paths like '/usr/bin' for unexpected modifications associated with 'docker cp' activity.
