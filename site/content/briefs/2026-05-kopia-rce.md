---
title: Kopia RCE via SSH ProxyCommand Injection (CVE-2026-45695)
slug: 2026-05-kopia-rce
description: 'Kopia''s HTTP server, when started without `--without-password`, accepts unauthenticated requests which can lead to arbitrary command execution as the Kopia process user via `-oProxyCommand` in `sshArguments` for SFTP backends with `externalSSH: true`. An attacker-supplied storage configuration is forwarded to `blob.NewStorage`, and the `sshArguments` are split on spaces and passed directly to `exec.CommandContext("ssh")`, resulting in command injection.'
date: "2026-05-19T19:20:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - vulnerability
  - command-injection
  - kopia
  - CVE-2026-45695
vendors:
  - github
products:
  - kopia (<= 0.22.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1552
    technique_name: Unprotected Credentials
references:
  - https://github.com/advisories/GHSA-2q4c-3mrw-63c3
  - https://github.com/kopia/kopia/blob/v0.22.3/internal/server/server_authz_checks.go#L61-L73
  - https://github.com/kopia/kopia/blob/v0.22.3/repo/blob/sftp/sftp_storage.go#L448-L468
  - https://github.com/kopia/kopia/pull/5354
rules:
  - title: Detects CVE-2026-45695 Exploitation — Kopia Unauthenticated RCE via SSH ProxyCommand Injection
    description: Detects CVE-2026-45695 exploitation — HTTP POST to /api/v1/repo/exists with ProxyCommand in the request body indicating command injection attempt
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1552
    data_sources:
      - webserver
  - title: Detects CVE-2026-45695 Exploitation — Suspicious SSH Command Line Arguments
    description: Detects suspicious process executions of ssh with ProxyCommand or other potentially malicious command line arguments.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1552
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Kopia is vulnerable to remote command execution (CVE-2026-45695) when its HTTP server is started without authentication (`--without-password`) and configured to use an SFTP backend with `externalSSH: true`. This configuration flaw allows unauthenticated attackers to send a crafted HTTP request to the `/api/v1/repo/exists` endpoint. The vulnerability stems from the lack of proper input validation of `sshArguments` within the SFTP storage configuration. An attacker can inject arbitrary commands by including `-oProxyCommand=<cmd>` in the `sshArguments`. This leads to command execution as the Kopia process user due to how OpenSSH handles the `ProxyCommand` option. This issue affects Kopia versions 0.22.3 and earlier.

## Attack Chain

1. Kopia HTTP server is started without authentication using the `--without-password` flag.
2. The server is configured to use an SFTP backend with `externalSSH: true`.
3. Attacker sends an unauthenticated HTTP POST request to the `/api/v1/repo/exists` endpoint.
4. The request contains a crafted JSON body with malicious `sshArguments` including `-oProxyCommand=<malicious_command>`.
5. The server's `handleUIPossiblyNotConnected` function authorizes the request due to the missing authentication.
6. The `blob.NewStorage` function processes the attacker-supplied storage configuration.
7. Within the SFTP backend logic, `opt.SSHArguments` are populated from the JSON request body.
8. The `sshArguments` string is split on spaces and passed directly to `exec.CommandContext("ssh", ...)` without proper sanitization.
9. OpenSSH executes the injected command via `$SHELL -c <malicious_command>` before any TCP connection is attempted.
10. The attacker achieves arbitrary command execution as the Kopia process user.

## Impact

Successful exploitation of CVE-2026-45695 allows unauthenticated attackers to execute arbitrary commands on the Kopia server. There is no need for user interaction or valid credentials. The attacker gains the privileges of the Kopia process user, potentially leading to complete system compromise. The impact includes data exfiltration, system disruption, or further lateral movement within the network.

## Recommendation

*   Upgrade to Kopia version 0.22.4 or later, which includes the fix described in [https://github.com/kopia/kopia/pull/5354](https://github.com/kopia/kopia/pull/5354). This disables starting a server without a password that also listens on a non-loopback interface.
*   If upgrading is not immediately feasible, ensure that the Kopia HTTP server is never started without authentication (`--server-username` or `--server-password`).
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts of CVE-2026-45695.
*   Monitor web server logs for suspicious POST requests to the `/api/v1/repo/exists` endpoint with unusual `sshArguments` in the request body.
