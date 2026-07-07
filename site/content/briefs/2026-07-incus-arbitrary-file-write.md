---
title: Incus Client Arbitrary File Write via Malicious Image Hash (CVE-2026-48769)
slug: 2026-07-incus-arbitrary-file-write
description: A critical arbitrary file write vulnerability (CVE-2026-48769) exists in the Incus client daemon (`incusd`) when processing images from a malicious server, allowing an attacker to inject path traversal into the `Incus-Image-Hash` header to create arbitrary files in sensitive locations as root, ultimately leading to arbitrary command execution.
date: "2026-07-03T10:34:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - arbitrary-file-write
  - path-traversal
  - rce
  - incus
  - linux
  - cve
vendors:
  - lxc
products:
  - Incus (< 7.2.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: An arbitrary file write on the client with root privileges; possibly leading to arbitrary command execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By writing a crafted cron job, an attacker can achieve arbitrary command execution as root.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: |
      cron payload: * * * * * root /bin/sh -c {shlex.quote(command)}
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-f6m5-xw2g-xc4x
iocs:
  - type: url
    value: http://attacker/payload
ioc_counts:
  url: 1
rules:
  - title: Detect Incus Daemon Arbitrary File Write via CVE-2026-48769
    description: Detects CVE-2026-48769 exploitation — suspicious file creation by the 'incusd' daemon in sensitive directories like /etc/cron.d, indicating a path traversal vulnerability has been exploited.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
      - privilege_escalation
    techniques:
      - T1053.003
      - T1059.004
      - T1548.001
    data_sources:
      - file_event
      - linux
rules_count: 1
---

A critical arbitrary file write vulnerability, tracked as CVE-2026-48769, affects the Incus client daemon (`incusd`) versions prior to 7.2.0. This flaw stems from improper validation of the `Incus-Image-Hash` HTTP header when `incusd` imports an image from a remote URL. A malicious Incus image server can craft this header to include path traversal sequences (e.g., `../../../../etc/cron.d/`), tricking `incusd` into writing an arbitrary file to a sensitive location on the host system with root privileges. By leveraging this to create a cron job (e.g., `/etc/cron.d/incus-direct-image-url-rce`), an attacker can achieve arbitrary command execution as root, leading to full system compromise and privilege escalation. This vulnerability poses a significant risk to Incus environments where image imports from untrusted sources are permitted.

## Attack Chain

1.  An attacker sets up a malicious Incus image server controlled by them.
2.  The victim's Incus server (`incusd` daemon) is instructed to import an image using a user-supplied URL pointing to the attacker-controlled server (e.g., via `incus image import <malicious_URL>`).
3.  `incusd` initiates a HEAD request to the attacker's server to retrieve image metadata.
4.  The malicious server responds with a crafted `Incus-Image-Hash` HTTP header containing a path traversal sequence (e.g., `../../../../etc/cron.d/incus-direct-image-url-rce`) and an `Incus-Image-URL` header pointing to the malicious payload.
5.  `incusd` processes these headers, and its `imageDownload()` function constructs a file path by combining `/var/lib/incus/images/` with the attacker-supplied hash. Due to the path traversal, this resolves to a sensitive system path, such as `/etc/cron.d/incus-direct-image-url-rce`.
6.  `incusd` invokes `os.Create()` on this crafted path, creating the arbitrary file `/etc/cron.d/incus-direct-image-url-rce` with root privileges.
7.  `incusd` then makes a GET request to the `Incus-Image-URL` provided by the attacker and writes the malicious content (e.g., a cron job command `* * * * * root /bin/sh -c "id > /tmp/incus-direct-image-url-rce"`) into the newly created file.
8.  The host system's cron daemon subsequently executes the newly installed cron job, resulting in arbitrary command execution as root, enabling the attacker to gain full control over the Incus server.

## Impact

Successful exploitation of CVE-2026-48769 allows an attacker to achieve an arbitrary file write on the Incus host system with root privileges. This directly leads to arbitrary command execution by writing malicious cron jobs or other configuration files, effectively compromising the entire server. This includes potential for data exfiltration, further lateral movement, or installation of persistent backdoors. Systems running Incus versions prior to 7.2.0 that import images from untrusted sources are at severe risk of compromise. While no specific victim counts are detailed, any organization utilizing vulnerable Incus deployments is susceptible.

## Recommendation

*   Patch CVE-2026-48769 immediately by upgrading Incus to version 7.2.0 or later on all affected Linux servers.
*   Deploy the Sigma rule in this brief to your SIEM to detect suspicious file creations by the `incusd` process in sensitive system directories.
*   Implement strict controls over which Incus image servers are trusted and limit the ability of non-administrative users to import images from arbitrary URLs.
*   Enable comprehensive file system logging (e.g., auditd for Linux) to detect unexpected file creations or modifications in sensitive directories like `/etc/cron.d/`.
