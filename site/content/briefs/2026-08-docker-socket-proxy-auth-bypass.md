---
title: Insufficient Access Control in docker-socket-proxy
slug: 2026-08-docker-socket-proxy-auth-bypass
description: An access control vulnerability in docker-socket-proxy (CVE-2026-78122) allows unauthenticated adjacent attackers to bypass restrictions and exfiltrate container filesystems via unauthorized API requests.
date: "2026-08-22T23:33:32Z"
lastmod: "2026-08-23T03:52:39Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=2DDF171A-EC6F-5014-AC4E-DBE83BFEDB8A&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - container-security
  - api-security
vendors:
  - Tecnativa
products:
  - docker-socket-proxy
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Attackers can use GET requests to /containers/{id}/archive, /containers/{id}/export, /containers/{id}/logs, and /containers/{id}/top to read arbitrary files and download entire container filesystems as tar archives.
    confidence_band: high
cves:
  - id: CVE-2026-78122
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78122
  - https://www.vulncheck.com/advisories/docker-socket-proxy-through-insufficient-access-control-granularity-exposes-container-filesystems
  - https://sploitus.com/exploit?id=2DDF171A-EC6F-5014-AC4E-DBE83BFEDB8A&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-78122 Exploitation Attempt
    description: Detects unauthorized GET requests to sensitive Docker container endpoints that should be gated by the proxy
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1530
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Review docker-socket-proxy configuration for exposure of sensitive container endpoints
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-78122 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade docker-socket-proxy to a patched version beyond 0.5.0
      owner: IT Operations
      addresses: CVE-2026-78122
      evidence: Source advisory
updates:
  - at: "2026-08-23T03:52:39Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=2DDF171A-EC6F-5014-AC4E-DBE83BFEDB8A&utm_source=rss&utm_medium=rss
---

Tecnativa docker-socket-proxy version 0.5.0 and earlier contains an access control vulnerability identified as CVE-2026-78122. The vulnerability arises when the 'CONTAINERS' environment variable is enabled, intended to gate access to specific Docker API endpoints. Due to insufficient granularity in the HAPROXY configuration, the proxy fails to properly restrict read-only endpoints in the /containers namespace. An unauthenticated attacker positioned on the adjacent network can issue GET requests to sensitive endpoints, including /containers/{id}/archive and /containers/{id}/export. Successful exploitation allows the attacker to download entire container filesystems as tar archives, read container logs, and inspect process information via /top. This vulnerability poses a significant risk to environments relying on the proxy to isolate the Docker socket from unauthorized network entities.

## Impact

The impact of this vulnerability includes the unauthorized disclosure of sensitive data contained within running container filesystems. Successful exploitation enables attackers to extract configuration files, environment variables, source code, and secrets present in the container images. This could lead to further compromise of the underlying infrastructure or linked services.

## Recommendation

- Upgrade to a version of docker-socket-proxy that resolves the configuration flaw in the HAPROXY ruleset.
- Review and tighten the HAPROXY access control lists (ACLs) to ensure only authorized endpoints are reachable, explicitly denying access to /archive and /export unless strictly required.
- Monitor logs for unauthorized GET requests to the /containers API namespace originating from untrusted network segments.
- Restrict network access to the docker-socket-proxy service to only explicitly authorized client IPs using firewall or network security group rules.
