---
title: Nginx-UI Unauthenticated Remote Code Execution via Backup Restore
slug: 2026-05-nginx-ui-rce
description: Nginx-UI is vulnerable to unauthenticated remote code execution (RCE) via the `POST /api/restore` endpoint, allowing attackers to inject arbitrary commands into the configuration.
date: "2026-05-07T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - authentication bypass
  - command injection
  - nginx-ui
  - devops
vendors:
  - nginx
products:
  - nginx-ui
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-4pvg-prr3-9cxr
rules:
  - title: Detect Nginx-UI Configuration Restore with Suspicious TestConfigCmd
    description: Detects attempts to exploit the Nginx-UI unauthenticated RCE vulnerability by monitoring process creation events for the execution of suspicious commands from TestConfigCmd.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Nginx-UI API Access with Default Node Secret
    description: Detects attempts to access Nginx-UI API endpoints using a default or weak Node Secret, potentially indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Nginx-UI is vulnerable to an unauthenticated remote code execution (RCE) vulnerability. The vulnerability resides in the `POST /api/restore` endpoint, which lacks authentication for the first 10 minutes after a fresh installation or after each process restart. An attacker can exploit this by uploading a malicious backup archive containing a crafted `app.ini` file. The crafted `app.ini` is then used to overwrite the existing configuration. By injecting an arbitrary OS command into the `TestConfigCmd` setting within the restored `app.ini`, an attacker can execute arbitrary commands as the user running nginx-ui, typically `root` in Docker deployments. This occurs upon application restart triggered by the restore process and a subsequent API call to trigger the `TestConfig` function. This vulnerability allows a complete takeover of the Nginx-UI instance and potentially the host system.

## Attack Chain

1.  The attacker accesses the `/api/install` endpoint to confirm that the installation window is open and authentication is not required.
2.  The attacker crafts a malicious backup archive containing `manifest.json`, `manifest.sig`, `nginx-ui.zip`, and `nginx.zip`, as per the defined format. The `nginx-ui.zip` contains a malicious `app.ini` file with an injected OS command within the `TestConfigCmd` setting.
3.  The attacker calculates the HMAC-SHA256 signature of `manifest.json` using the attacker-supplied AES key to bypass the integrity check.
4.  The attacker sends a `POST` request to the `/api/restore` endpoint with the crafted backup file and a security token containing the AES key and IV in base64 format, setting `restore_nginx_ui` to `true`.
5.  The Nginx-UI application restores the crafted `app.ini` file, overwriting the existing configuration.
6.  The application restarts after a 2-second delay, loading the attacker's malicious `app.ini` configuration.
7.  The attacker sends a `POST` request to the `/api/nginx/test` endpoint, authenticating with the node secret set in the malicious `app.ini`.
8.  The application executes the injected OS command from the `TestConfigCmd` setting within the `app.ini` file, granting the attacker code execution on the server as the nginx-ui process user.

## Impact

Successful exploitation of this vulnerability can lead to complete system compromise. An attacker can gain full read access to sensitive data, including Nginx configurations, TLS private keys, database contents, and secrets stored in `app.ini`. They can also arbitrarily modify Nginx configurations and Nginx-UI application state, leading to denial of service. In Docker deployments, where Nginx-UI often runs as root, the attacker can gain full host access if the container has host mounts or privileged mode enabled.

## Recommendation

*   Apply the primary fix by requiring authentication unconditionally on the `/api/restore` endpoint as described in the advisory.
*   Implement the secondary fix by validating the content of the restored `app.ini` file, specifically rejecting or stripping `TestConfigCmd`, `ReloadCmd`, and `RestartCmd` from any externally-supplied backup.
*   Deploy the Sigma rule "Detect Nginx-UI Configuration Restore with Suspicious TestConfigCmd" to detect attempts to exploit this vulnerability by monitoring process creation events with unusual commands.
*   Monitor network traffic for suspicious outbound connections initiated by the Nginx-UI process after a configuration restore, which may indicate command execution as described in the attack chain.
