---
title: Portainer Bind Mount Restriction Bypass via HostConfig.Mounts (CVE-2026-44850)
slug: 2026-05-portainer-bind-mount-bypass
description: Portainer versions 2.33.0 through 2.33.7, 2.39.0 through 2.39.1, and 2.40.0 through 2.40.9 are vulnerable to CVE-2026-44850, a bind-mount restriction bypass via the `HostConfig.Mounts` array allowing regular users to mount host paths into containers and potentially compromise the host filesystem.
date: "2026-05-14T16:30:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - container
  - CVE-2026-44850
vendors:
  - Portainer
products:
  - Portainer (>= 2.33.0, < 2.33.8)
  - Portainer (>= 2.39.0, < 2.39.2)
  - Portainer (>= 2.40.0, < 2.41.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
references:
  - https://github.com/advisories/GHSA-7fw3-x4r2-g7wc
  - CVE-2026-44850
rules:
  - title: Detect Portainer HostConfig Mounts Bind Type (CVE-2026-44850)
    description: 'Detects CVE-2026-44850 exploitation — Container creation with HostConfig.Mounts of Type: bind, indicating a bind mount attempt.'
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
  - title: Detect Portainer API container creation with HostConfig Mounts
    description: Detects container creation API calls that include the HostConfig Mounts parameter, which might indicate exploitation attempts of the Portainer bind mount bypass vulnerability (CVE-2026-44850).
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - webserver
rules_count: 2
---

Portainer, a container management platform, contains a vulnerability (CVE-2026-44850) where the "Disable bind mounts for non-administrators" security setting can be bypassed. This setting aims to prevent regular users from binding host paths into containers they create through the Portainer-mediated Docker API. However, the check only inspected the `HostConfig.Binds` array and not the equivalent `HostConfig.Mounts` array. An authenticated user with container-create rights on an environment where the restriction is enabled could exploit this vulnerability and mount any host path into their container by submitting a `bind`-typed entry under `HostConfig.Mounts`. This bypass can be exploited to gain unauthorized access to the Docker host's filesystem, compromising the entire system. Fixes were released in versions 2.33.8, 2.39.2, and 2.41.0.

## Attack Chain

1. An attacker authenticates to Portainer as a regular user with container-create rights.
2. The targeted Portainer environment has the "Disable bind mounts for non-administrators" security setting enabled.
3. The attacker crafts a `POST /containers/create` request to the Docker API through the Portainer proxy.
4. In the request body, the attacker includes a `HostConfig.Mounts` array with a `bind`-typed entry. This entry specifies the host path to be mounted into the container.
5. The Portainer proxy, which only checks `HostConfig.Binds`, fails to detect the malicious bind mount configuration in `HostConfig.Mounts`.
6. The Docker daemon creates the container with the specified bind mount, granting the attacker's container access to the host filesystem.
7. The attacker executes commands within the container to read or write to the mounted host path, potentially accessing sensitive data or modifying system configurations.
8. The attacker compromises the host system, other containers, or achieves persistence by writing to authorized_keys or systemd units.

## Impact

Successful exploitation allows a regular user to bypass bind mount restrictions and gain unauthorized access to the Docker host filesystem. This can lead to:

- Reading or writing any path on the Docker host filesystem, including sensitive files like `/etc/shadow` or SSH keys under `/root/.ssh`.
- Compromising other containers on the same host by accessing their layers, volumes, and live state within `/var/lib/docker`.
- Gaining full Docker API access by mounting `/var/run/docker.sock` into the container.
- Writing persistence to the host by dropping SSH keys into `authorized_keys` or installing systemd units.

This vulnerability affects installations where the bind-mount restriction was relied upon as the primary defense against host exposure, particularly in shared environments with non-administrator container creators.

## Recommendation

- Upgrade Portainer to versions 2.33.8, 2.39.2, or 2.41.0 or later to patch CVE-2026-44850.
- Deploy the Sigma rule `Detect Portainer HostConfig Mounts Bind Type (CVE-2026-44850)` to detect attempts to exploit this vulnerability by monitoring container creation events.
- Audit recent container creations for `HostConfig.Mounts` of `Type: bind` from non-admin Portainer users as suggested in the advisory.
- Revoke container-create rights from non-administrator accounts on affected environments until the patched release is deployed as described in the advisory.
