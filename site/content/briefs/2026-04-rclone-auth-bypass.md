---
title: Rclone Unauthenticated options/set Allows Runtime Auth Bypass
slug: 2026-04-rclone-auth-bypass
description: Rclone is vulnerable to an unauthenticated options/set vulnerability that allows runtime authentication bypass, potentially leading to sensitive operations and command execution by setting `rc.NoAuth=true` on reachable RC servers started without global HTTP authentication.
date: "2026-04-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rclone
  - auth-bypass
  - rc-api
  - CVE-2026-41176
  - command-execution
vendors:
  - rclone
products:
  - rclone
affected_os:
  - Ubuntu
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-25qr-6mpr-f7qx
rules:
  - title: Detect Rclone Unauthenticated options/set
    description: Detects unauthenticated POST requests to the `/options/set` endpoint of the Rclone RC API, used to disable authentication.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Rclone Core Command Execution via RC API
    description: Detects POST requests to the `/core/command` endpoint of the Rclone RC API, indicating potential command execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Rclone, a command-line program to manage files on cloud storage, is vulnerable to an authentication bypass via its remote control (RC) API. The vulnerability, present from version 1.45 onwards, stems from the `options/set` endpoint being exposed without authentication requirements, while still being able to modify the global runtime configuration.  An unauthenticated attacker can exploit this vulnerability by setting the `rc.NoAuth` parameter to `true`, effectively disabling the authentication gate for numerous RC methods registered with `AuthRequired: true`. This allows unauthorized access to sensitive administrative functionality, including configuration settings and operational commands. The issue was validated against `v1.73.4` and the current `master` branch as of April 14, 2026. This vulnerability is especially critical when the RC API is exposed without global HTTP authentication (i.e. `--rc-user`/`--rc-pass` are not set), as it allows complete control of the Rclone instance.

## Attack Chain

1. An attacker identifies a vulnerable Rclone instance with the RC API enabled (via `--rc` or `rclone rcd`) that is reachable on the network. The attacker confirms that the RC API is not protected by global HTTP authentication (no `--rc-user`, `--rc-pass`, or `--rc-htpasswd` flags).
2. The attacker sends an unauthenticated POST request to the `/options/set` endpoint with a JSON payload setting `rc.NoAuth` to `true`: `{"rc":{"NoAuth":true}}`.
3. The Rclone RC server processes the request and updates the runtime configuration, disabling the authentication requirement for subsequent RC calls.
4. The attacker leverages the now-unprotected RC API to access sensitive configuration data using endpoints like `/config/listremotes`, `/config/dump`, or `/config/get`.
5. The attacker can list the available filesystems and remote configurations.
6. The attacker then uses operational endpoints such as `/operations/list` to list files and directories within a configured remote.
7. The attacker exploits the `/operations/copyfile` endpoint to copy files from one location to another, potentially exfiltrating sensitive data or overwriting critical files.
8. Finally, the attacker uses the `/core/command` endpoint to execute arbitrary commands on the host system, achieving complete system compromise. This endpoint utilizes the `exec.Command(...)` function, allowing arbitrary command execution.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to bypass intended access controls on the Rclone RC administrative interface. The impact ranges from sensitive configuration disclosure and filesystem enumeration to arbitrary command execution on the host system. This could lead to complete system compromise, data exfiltration, or denial of service.  The vulnerability affects Rclone instances from version 1.45 up to (but not including) 1.73.5. The severity is amplified when the RC API is exposed to a wider network without proper authentication measures.

## Recommendation

*   Upgrade Rclone to version 1.73.5 or later to patch CVE-2026-41176.
*   If upgrading is not immediately feasible, ensure that the Rclone RC API is protected by global HTTP authentication using the `--rc-user`, `--rc-pass`, or `--rc-htpasswd` flags.
*   Monitor network traffic for POST requests to the `/options/set` endpoint without authentication, indicative of exploitation attempts. Deploy the provided Sigma rule to detect this activity.
*   Review Rclone RC API access logs for unauthorized access to sensitive endpoints such as `/config/listremotes`, `/config/dump`, `/config/get`, `/operations/list`, `/operations/copyfile`, and `/core/command` after the `/options/set` endpoint has been accessed.
