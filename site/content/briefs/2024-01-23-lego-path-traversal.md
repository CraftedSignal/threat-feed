---
title: Lego ACME Client Arbitrary File Write via Path Traversal
slug: 2024-01-23-lego-path-traversal
description: The lego ACME client is vulnerable to arbitrary file write and deletion via path traversal, where a malicious ACME server can supply a crafted challenge token containing `../` sequences, causing lego to write attacker-influenced content to any path writable by the lego process, potentially leading to remote code execution, data destruction, or privilege escalation.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - acme
  - lego
  - certificate-management
  - cve-2026-40611
vendors:
  - go-acme
products:
  - lego
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-qqx8-2xmm-jrv8
rules:
  - title: Detect Lego Path Traversal Attempt via Challenge Token
    description: Detects attempts to exploit the Lego ACME client path traversal vulnerability by monitoring for process creation events where the lego executable is used with a malicious ACME server and potentially a path traversal sequence in the command line arguments.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1552.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Arbitrary File Write Outside Webroot by Lego
    description: This rule detects file creation events outside the intended webroot directory by the lego process, indicating a potential path traversal exploit.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The `go-acme/lego` library, a popular ACME client, is susceptible to a path traversal vulnerability within its webroot HTTP-01 challenge provider. This flaw allows a malicious ACME server to manipulate the file paths used by `lego` when responding to certificate requests. By providing a crafted challenge token containing `../` sequences, the attacker can force `lego` to write data to arbitrary locations on the filesystem, bypassing the intended webroot directory. This vulnerability affects versions prior to 4.34.0 (v4), 3.9.0 (v3), and 2.7.2 (v2), potentially impacting any system where `lego` is used for automated certificate management. Successful exploitation could lead to remote code execution, data destruction, or privilege escalation, depending on the context and permissions of the `lego` process.

## Attack Chain

1.  Victim configures `lego` to use a malicious ACME server using the `--server` flag.
2.  Victim specifies a webroot directory using the `--http.webroot` flag, such as `/var/www/html`.
3.  Victim initiates a certificate request using `lego run` with a targeted domain.
4.  The malicious ACME server responds with a crafted challenge token containing path traversal sequences like `../../../../../../tmp/evil`.
5.  `lego` concatenates the webroot path with the malicious token using `filepath.Join()`.
6.  `lego` calls `os.MkdirAll()` to create the directory structure for the file path.
7.  `lego` writes the key authorization content to the file path resolved with path traversal via `os.WriteFile()`.
8.  The key authorization is written to an arbitrary location (e.g., `/tmp/evil`) outside of the webroot, and could be used to overwrite config files, systemd units, etc.

## Impact

This path traversal vulnerability (CVE-2026-40611) allows a malicious ACME server to write arbitrary files to the filesystem. Any user running `lego` with the HTTP-01 challenge solver against a malicious or compromised ACME server is affected. This can lead to remote code execution by writing to cron directories, systemd unit paths, shell profiles, or web application directories served by the webroot. Data can be destroyed by overwriting configuration files, TLS certificates, or application state. Privilege escalation is possible if `lego` runs as root, granting unrestricted filesystem write access. The `CleanUp()` function also enables arbitrary file deletion using the same unsanitized token.

## Recommendation

*   Upgrade `go-acme/lego` to version 4.34.0 or later to patch CVE-2026-40611.
*   Implement input validation on the ACME token received from the ACME server to prevent path traversal sequences.
*   Deploy the Sigma rule "Detect Lego Path Traversal Attempt via Challenge Token" to identify attempts to exploit the vulnerability (see below).
*   Monitor filesystem writes performed by the `lego` process, especially to sensitive directories. Enable Sysmon file creation logging to facilitate this monitoring.
