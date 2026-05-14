---
title: Portainer Missing Authorization on Docker Plugin Endpoints Leads to Host RCE (CVE-2026-44848)
slug: 2026-05-portainer-rce
description: Portainer versions 2.33.0 through 2.33.7, 2.39.0 through 2.39.1, and 2.40.0 expose a missing authorization vulnerability (CVE-2026-44848) on the Docker plugin management endpoints, allowing a non-admin user with access to a Docker endpoint to install and enable arbitrary Docker plugins from any registry, ultimately leading to root privileges on the Docker host and unauthorized file system access.
date: "2026-05-14T16:29:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - execution
  - CVE-2026-44848
vendors:
  - Portainer
products:
  - Portainer (>= 2.33.0, < 2.33.8)
  - Portainer (>= 2.39.0, < 2.39.2)
  - Portainer (>= 2.40.0, < 2.41.0)
  - Docker
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
references:
  - https://github.com/advisories/GHSA-rrmm-9v76-h3p4
  - CVE-2026-44848
rules:
  - title: Detect CVE-2026-44848 Exploitation — Portainer Unauthorized Plugin Pull
    description: Detects CVE-2026-44848 exploitation — attempts to pull Docker plugins via the Portainer API without proper authorization.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-44848
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - webserver
  - title: Detect CVE-2026-44848 Exploitation — Portainer Unauthorized Plugin Enable
    description: Detects CVE-2026-44848 exploitation — attempts to enable Docker plugins via the Portainer API without proper authorization.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-44848
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - webserver
rules_count: 2
---

Portainer, a web-based management UI for Docker, has a critical missing authorization vulnerability (CVE-2026-44848) affecting versions 2.33.0-2.33.7, 2.39.0-2.39.1, and 2.40.0. This flaw allows a standard (non-admin) user with access to a Docker endpoint to bypass Role-Based Access Control (RBAC) and directly interact with the Docker daemon's plugin management endpoints.  Specifically, the `/plugins/*` endpoints were not properly registered with an authorization handler. This oversight enables a malicious user to install, enable, and execute arbitrary Docker plugins, gaining root-level privileges on the underlying Docker host. This vulnerability was reported on 2026-03-16 and patched in subsequent releases, highlighting the importance of timely updates for Portainer deployments.

## Attack Chain

1.  A non-admin user authenticates to Portainer with access to a Docker endpoint.
2.  The user crafts a `POST` request to the `/plugins/pull` endpoint, specifying a malicious Docker plugin from a public or private registry.
3.  Portainer forwards the request to the Docker daemon without proper authorization checks, bypassing RBAC.
4.  Docker pulls the specified plugin image from the registry.
5.  The user crafts a `POST` request to the `/plugins/{name}/enable` endpoint to enable the pulled plugin.
6.  Again, Portainer forwards the request to the Docker daemon without authorization.
7.  Docker enables the plugin, granting it requested privileges such as `CAP_SYS_ADMIN` and host-path mounts.
8.  The malicious Docker plugin executes with root privileges on the Docker host, allowing the user to read and modify files, effectively gaining complete control of the system.

## Impact

This vulnerability allows an attacker with limited Portainer privileges to achieve root-level access on the Docker host. The attacker can then read and modify sensitive data, install malware, or disrupt services. Given the widespread use of Portainer in managing Docker environments, a successful exploit could lead to significant data breaches, system compromise, and operational disruption.  Organizations using vulnerable Portainer versions are at high risk and should apply the provided patches or workarounds immediately.

## Recommendation

*   **Upgrade Portainer:** Immediately upgrade to the latest version of your supported branch (2.33.8, 2.39.2, or 2.41.0) to address the vulnerability as indicated in the advisory.
*   **Apply Workaround:** As an interim measure, revoke Docker endpoint access for non-admin users via Portainer RBAC until the patched release is deployed as suggested in the "Workarounds" section.
*   **Monitor Docker API Access:** Implement network monitoring to detect unauthorized access to the Docker API, focusing on `/plugins/*` endpoints, to catch potential exploit attempts.
