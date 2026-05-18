---
title: Docker `PUT /containers/{id}/archive` Vulnerability Allows Host Root Code Execution
slug: 2026-05-docker-archive-rce
description: A vulnerability exists in Docker where a malicious container image can execute arbitrary code with host root privileges by exploiting the decompression of compressed archives uploaded via the `PUT /containers/{id}/archive` endpoint, tracked as CVE-2026-41567.
date: "2026-05-18T17:47:42Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - docker
  - container
  - rce
  - privilege-escalation
  - CVE-2026-41567
vendors:
  - Docker
  - Moby
products:
  - Docker (<= 28.5.2)
  - moby/moby (<= 28.5.2)
  - moby/moby/v2 (< 2.0.0-beta.14)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
references:
  - https://github.com/advisories/GHSA-x86f-5xw2-fm2r
  - CVE-2026-41567
rules:
  - title: Detect Docker Archive Extraction from Container
    description: Detects processes running within a Docker container attempting to execute archive extraction tools, potentially indicating CVE-2026-41567 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-41567
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
  - title: Detect Docker cp of Compressed Archive
    description: Detects the use of `docker cp` command with a compressed archive, which could be used to exploit CVE-2026-41567.
    platform: sigma
    severity: low
    tactics:
      - cve-2026-41567
      - initial_access
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability, identified as CVE-2026-41567, exists in Docker related to the handling of compressed archives uploaded via the `PUT /containers/{id}/archive` endpoint. When a user uploads a compressed archive into a container, a malicious image can execute arbitrary code with daemon (host root) privileges. The vulnerability stems from the Docker daemon incorrectly resolving decompression binaries from the container's filesystem instead of the host's when handling `PUT /containers/{id}/archive` requests with compressed archives. This allows a container image containing a trojanized decompression binary (e.g., xz or gzip) to achieve code execution as the daemon process whenever a compressed archive is uploaded to that container. This issue affects Docker versions up to 28.5.2, moby/moby versions up to 28.5.2, and go/github.com/moby/moby/v2 versions prior to 2.0.0-beta.14.

## Attack Chain

1. An attacker crafts a malicious Docker image containing a trojanized decompression binary (e.g., `xz` or `gzip`).
2. The attacker deploys the malicious Docker image to a system.
3. A user runs a container from the malicious image.
4. The user uploads a compressed archive (either xz or gzip) into the container. This can be achieved by piping a compressed archive via `docker cp -` or by calling the `PUT /containers/{id}/archive` API directly with compressed content.
5. When processing the `PUT /containers/{id}/archive` request, the Docker daemon attempts to decompress the archive.
6. Due to the vulnerability, the Docker daemon executes the trojanized decompression binary from within the container's filesystem instead of using a trusted host binary.
7. The trojanized decompression binary executes arbitrary code with the privileges of the Docker daemon, which includes host root privileges.
8. The attacker gains control of the host system.

## Impact

Successful exploitation of this vulnerability leads to arbitrary code execution as host root, effectively bypassing the container-to-host trust boundary. This allows an attacker to gain full control of the host system, potentially leading to data exfiltration, system compromise, or other malicious activities.

## Recommendation

*   Upgrade to Docker version 28.5.3 or later to remediate CVE-2026-41567.
*   Apply available patches for `go/github.com/moby/moby/v2` before version 2.0.0-beta.14 to remediate CVE-2026-41567.
*   Implement authorization plugins to restrict access to the `PUT /containers/{id}/archive` endpoint, as recommended in the overview.
*   Avoid piping compressed archives into containers created from untrusted images, as discussed in the conditions for exploitation.
