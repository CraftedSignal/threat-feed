---
title: Moby Authorization Plugin Bypass via Oversized Request Bodies
slug: 2026-04-moby-authz-bypass
description: A vulnerability in Moby allows attackers to bypass authorization plugins by crafting API requests with oversized bodies, causing the Docker daemon to forward the request without the body to the plugin, potentially leading to unauthorized actions.
date: "2026-03-27T17:44:58Z"
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

A vulnerability exists in Moby (Docker) that can be exploited to bypass authorization plugins (AuthZ) when processing API requests. This vulnerability occurs because the Docker daemon may forward a request to an authorization plugin without the request body if the body is oversized. This incomplete fix for CVE-2024-41110 allows an attacker to craft a specific API request that triggers this behavior. This could lead to an AuthZ plugin making incorrect authorization decisions, potentially…
