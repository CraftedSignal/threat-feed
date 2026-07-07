---
title: 'motionEye Partial Authentication Bypass: Unauthenticated Admin Credential Theft via Path Traversal'
slug: 2026-07-motioneye-auth-bypass
description: Unauthenticated attackers can exploit a path traversal vulnerability in motionEye versions prior to 0.44.0 to read the application's configuration file, steal the admin SHA-1 password hash, and achieve full administrative access, leading to remote code execution.
date: "2026-07-03T10:49:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - authentication-bypass
  - remote-code-execution
  - credential-theft
  - web-application
products:
  - motionEye (< 0.44.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: an unauthenticated attacker can exploit a path traversal vulnerability to read the motionEye configuration file
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This allows reading any file on the filesystem that the motionEye process can access.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: motionEye stores the admin password as SHA1(plaintext) in its main configuration file (`motion.conf`)
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The result is full admin access from zero credentials.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Achieve RCE via the admin config API. The admin can set `command_notifications_exec` or `command_storage_exec` to arbitrary shell commands
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-phv5-334h-mxcw
rules:
  - title: Detect motionEye Unauthenticated Path Traversal for motion.conf
    description: Detects attempts to exploit the path traversal vulnerability (GHSA-phv5-334h-mxcw) in motionEye by attempting to read the motion.conf file via web server handlers like MoviePlaybackHandler.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1083
      - T1190
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability exists in motionEye versions prior to 0.44.0, enabling unauthenticated attackers to gain full administrative access and remote code execution. This is achieved by chaining two issues: a default configuration allowing unauthenticated access to normal-user endpoints when the normal user password is empty, and a path traversal vulnerability in several handlers (e.g., `MoviePlaybackHandler`). By exploiting the path traversal, an attacker can read the `motion.conf` file, which contains the admin password as a SHA-1 hash. This hash can then be used directly as a signing key to bypass authentication and gain full admin privileges without cracking. The scenario is realistic for home surveillance setups where the admin password protects settings, but camera feeds are left open for household members, making affected instances vulnerable to complete compromise.

## Attack Chain

1.  **Reconnaissance & Initial Access**: An attacker identifies a motionEye instance configured with an empty normal user password (default setting), allowing unauthenticated access to normal-level endpoints.
2.  **Path Traversal Exploitation**: The attacker crafts and sends an unauthenticated HTTP GET request to a vulnerable handler, such as `/movie/1/playback//etc/motioneye/motion.conf`, leveraging the path traversal vulnerability.
3.  **Information Disclosure**: The motionEye server's `MoviePlaybackHandler` (or similar) processes the malicious path, bypassing intended directory restrictions due to overridden safety checks, and reads the `motion.conf` file from the filesystem.
4.  **Credential Theft**: The server's response contains the content of `motion.conf`, from which the attacker extracts the admin password's SHA-1 hash, stored as a comment line (e.g., `# @admin_password 7b7d...`).
5.  **Authentication Bypass**: The attacker uses the stolen SHA-1 hash directly as a signing key by setting the `meye_password_hash` cookie, authenticating as an administrator to the motionEye web interface.
6.  **Privilege Escalation & Remote Code Execution**: With full admin access, the attacker leverages the configuration API to inject arbitrary shell commands into motion event hooks (e.g., `command_notifications_exec`), which are then executed by the underlying `motion` daemon with the privileges of the motionEye process, achieving RCE.

## Impact

This vulnerability leads to a severe privilege escalation from zero credentials to full admin access on any motionEye installation where the admin password is set but the normal user password is left empty (a common default configuration). Attackers can achieve arbitrary file read, potentially accessing sensitive files like `/etc/passwd` or SSH keys, if permissions allow. The most critical impact is full remote code execution, as administrative control allows injecting and executing arbitrary shell commands via motion event hooks. This represents a significant security risk for compromised surveillance systems, with public instances easily discoverable via search engines like Shodan.

## Recommendation

*   **Patch motionEye**: Immediately upgrade all motionEye installations to version 0.44.0 or higher to remediate the path traversal vulnerability.
*   **Configure Passwords**: If possible, set a non-empty password for the normal user account to prevent unauthenticated access to normal-level endpoints, reducing the attack surface.
*   **Deploy Detection Rule**: Deploy the provided Sigma rule to your SIEM to detect attempts at path traversal for configuration files.
*   **Monitor Web Server Logs**: Actively monitor web server access logs for unusual GET requests containing absolute file paths, particularly those targeting sensitive configuration files or unexpected locations.
