---
title: Portainer Endpoint Security Bypass via Docker Swarm Service API
slug: 2026-05-portainer-swarm-bypass
description: Portainer is vulnerable to an endpoint security bypass via Swarm service create/update, enabling non-admin users with access to a Docker Swarm endpoint to bypass `EndpointSecuritySettings` restrictions and gain elevated privileges such as configuring services with elevated Linux capabilities, disabling syscall filtering and AppArmor confinement, setting arbitrary sysctl values, and mounting arbitrary host paths.
date: "2026-05-14T16:37:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - portainer
  - docker
  - swarm
  - privilege-escalation
  - vulnerability
  - CVE-2026-44849
vendors:
  - Portainer
  - Docker
products:
  - Portainer (>= 2.33.0, < 2.33.8)
  - Portainer (>= 2.39.0, < 2.39.2)
  - Portainer (>= 2.40.0, < 2.41.0)
  - Docker Swarm
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-5fxq-qcf3-244w
  - CVE-2026-44849
rules:
  - title: Detect CVE-2026-44849 Exploitation — Portainer Swarm Service Create with Elevated Capabilities
    description: Detects CVE-2026-44849 exploitation — attempts to create a Docker Swarm service via the Portainer API with elevated capabilities (e.g., CAP_SYS_ADMIN, ALL).
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect CVE-2026-44849 Exploitation — Portainer Swarm Service Update with Host Bind Mount
    description: Detects CVE-2026-44849 exploitation — attempts to update a Docker Swarm service via the Portainer API to mount a host directory.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

Portainer enforces `EndpointSecuritySettings` restrictions to limit container configurations for non-admin users. However, these restrictions are not fully applied when creating or updating Docker Swarm services through the Portainer API. A non-admin user with access to a Docker Swarm endpoint can bypass these security measures by using the `POST /services/create` or `POST /services/{id}/update` endpoints. This bypass allows the user to escalate privileges, gaining capabilities such as mounting arbitrary host paths, elevating Linux capabilities (e.g., `CAP_SYS_ADMIN`), disabling syscall filtering, and disabling AppArmor confinement. The vulnerability affects all Portainer releases with Docker Swarm support prior to versions 2.33.8, 2.39.2, and 2.41.0, undermining the administrator's security policy on Swarm-enabled endpoints. The volume driver local-bind variant was disclosed on 2026-03-12, and the Swarm service create/update bypass was disclosed on 2026-04-05.

## Attack Chain

1. An authenticated, non-admin user gains access to a Docker Swarm endpoint via Portainer RBAC.
2. The user crafts a `POST /services/create` request to create a new service, bypassing capability, sysctl, and security-opt checks.
3. Alternatively, the user creates a benign service and then sends a `POST /services/{id}/update` request to modify the service, bypassing all security checks.
4. The request includes configurations to elevate Linux capabilities (e.g., `CapabilityAdd: ["ALL"]`), disable syscall filtering (`Privileges.Seccomp.Mode: "unconfined"`), or disable AppArmor confinement (`Privileges.AppArmor.Mode: "disabled"`).
5. The request may also include configurations for arbitrary sysctl values inside the container namespace, and/or bind mounts of any host path, including sensitive paths such as `/`, `/var/run/docker.sock`, or SSH keys.
6. The Docker daemon creates or updates the service with the elevated privileges, bypassing Portainer's intended security restrictions.
7. The attacker can then leverage the elevated privileges to access the host filesystem (e.g., via `chroot /host`) or perform other actions with root-equivalent access on the Swarm manager host.
8. The final objective is to gain unauthorized access to sensitive data or systems, or to disrupt services running on the Docker Swarm cluster.

## Impact

Successful exploitation allows a non-admin Portainer user to escalate privileges and gain root-equivalent access on the Swarm manager host. This bypasses the administrator's security policy and enables the attacker to perform actions such as accessing sensitive data, modifying system configurations, or disrupting services. The impact is significant because it undermines the security model of Portainer and Docker Swarm, potentially leading to unauthorized access to critical infrastructure and data. The vulnerability affects every Portainer release with Docker Swarm support prior to versions 2.33.8, 2.39.2, and 2.41.0.

## Recommendation

- Upgrade Portainer to versions 2.33.8, 2.39.2, or 2.41.0 to remediate CVE-2026-44849.
- Until an upgrade can be performed, temporarily revoke Swarm endpoint access for non-admin users via Portainer RBAC, as described in the advisory.
- Implement a daemon-side allowlist to block the creation of local-driver volumes that use `type: none` / `o: bind` on untrusted endpoints, mitigating the volume-driver-bind variant of the vulnerability.
- Deploy the Sigma rules provided in this brief to your SIEM to detect exploitation attempts targeting the Portainer API.
