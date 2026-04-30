---
title: Moby Authorization Plugin Bypass via Oversized Request Bodies
slug: 2026-04-moby-authz-bypass
description: A vulnerability in Moby allows attackers to bypass authorization plugins by crafting API requests with oversized bodies, causing the Docker daemon to forward the request without the body to the plugin, potentially leading to unauthorized actions.
date: "2026-03-27T17:44:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - docker
  - authz
  - authorization
  - bypass
  - cve-2026-34040
references:
  - https://github.com/advisories/GHSA-x744-4wpc-v9h2
  - https://docs.docker.com/engine/extend/plugins_authorization/
  - https://github.com/moby/moby/security/advisories/GHSA-v23v-6jw2-98fq
rules:
  - title: Detect Docker API Requests without Request Body
    description: Detects requests to the Docker API that might be missing a request body.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: Detect potentially malicious usage of docker API via webserver logs
    description: Detects potentially malicious activities based on HTTP requests seen in webserver logs
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists in Moby (Docker) that can be exploited to bypass authorization plugins (AuthZ) when processing API requests. This vulnerability occurs because the Docker daemon may forward a request to an authorization plugin without the request body if the body is oversized. This incomplete fix for CVE-2024-41110 allows an attacker to craft a specific API request that triggers this behavior. This could lead to an AuthZ plugin making incorrect authorization decisions, potentially allowing unauthorized actions to be performed. This affects deployments that rely on AuthZ plugins that inspect the request body for access control. The vulnerable packages include `go/github.com/moby/moby` (versions prior to 29.3.1), `go/github.com/docker/docker` (versions prior to 29.3.1), and `go/github.com/moby/moby/v2` (versions prior to 2.0.0-beta.8).

## Attack Chain

1. Attacker identifies a Docker environment utilizing an AuthZ plugin that relies on request body inspection for authorization.
2. Attacker crafts a malicious Docker API request targeting a sensitive resource or action.
3. The attacker inflates the request body to exceed a size threshold that triggers the bypass behavior.
4. The Docker daemon receives the oversized API request.
5. Due to the vulnerability, the Docker daemon forwards the request to the AuthZ plugin without the request body.
6. The AuthZ plugin, lacking the request body, makes an authorization decision based on incomplete information.
7. The AuthZ plugin, unable to properly validate the request, grants access to the sensitive resource or action.
8. The attacker successfully executes the unauthorized action, bypassing the intended security controls.

## Impact

This vulnerability primarily impacts Docker environments that utilize authorization plugins and rely on request body inspection for access control decisions. If exploited successfully, an attacker can bypass the intended authorization mechanisms, potentially leading to unauthorized access to sensitive resources, data breaches, or other malicious activities within the containerized environment. The severity is high for affected installations, however, the base likelihood of exploitation is low, and only impacts those using AuthZ plugins.

## Recommendation

*   Upgrade to Moby version 29.3.1 or later to address the vulnerability. This resolves the incomplete fix for CVE-2024-41110 and prevents the AuthZ bypass.
*   For environments where immediate upgrades are not possible, avoid using AuthZ plugins that rely on request body inspection for security decisions as described in the overview.
*   Restrict access to the Docker API to trusted parties following the principle of least privilege to reduce the attack surface.
