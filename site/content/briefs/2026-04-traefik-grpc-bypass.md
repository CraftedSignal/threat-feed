---
title: Traefik gRPC Deny Rule Bypass Vulnerability (CVE-2026-33186)
slug: 2026-04-traefik-grpc-bypass
description: A remote, unauthenticated attacker can bypass Traefik deny rules by sending malformed gRPC requests with a missing leading slash in the `:path` pseudo-header, exploiting a vulnerability in the gRPC-Go dependency, leading to unauthorized access if a fallback "allow" rule is configured.
date: "2026-03-29T15:37:47Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - traefik
  - grpc
  - authorization-bypass
  - cve-2026-33186
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Bypass User Account Control
references:
  - https://github.com/advisories/GHSA-46wh-3698-f2cx
rules:
  - title: Detect Traefik gRPC Path Bypass Attempt
    description: Detects attempts to bypass Traefik's authorization by sending gRPC requests with a malformed :path header (missing leading slash).
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Traefik gRPC Path Bypass Attempt - HTTP Method Check
    description: Detects attempts to bypass Traefik's authorization by sending gRPC requests with a malformed :path header, also checking for POST method.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Traefik, a popular reverse proxy and load balancer, is susceptible to a denial rule bypass (CVE-2026-33186) due to a flaw in its gRPC-Go dependency. This vulnerability affects Traefik versions prior to 2.11.42, versions 3.0.0-beta3 through 3.6.11, and versions 3.7.0-ea.1 through 3.7.0-ea.3. An unauthenticated attacker can exploit this by sending gRPC requests with a malformed HTTP/2 `:path` pseudo-header that omits the leading slash (e.g., `Service/Method` instead of `/Service/Method`). While…
