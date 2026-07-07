---
title: 'motionEye: LFI → Pass-the-Hash Admin → Unsafe Restore → Unauthenticated Action Execution (RCE)'
slug: 2026-07-motioneye-rce-chain
description: An attacker can chain multiple vulnerabilities in motionEye, including an arbitrary file read (LFI), a signature bypass using password hashes, and an unsafe configuration restore, to achieve unauthenticated remote code execution (RCE) if the normal user password is unset, or authenticated RCE from a normal user account.
date: "2026-07-03T10:57:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - RCE
  - LFI
  - motioneye
  - vulnerability
  - unauthenticated
  - privilege-escalation
vendors:
  - motionEye project
products:
  - motionEye (0.44.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An arbitrary file read (LFI) via the picture download endpoint for local motion cameras using absolute paths.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Read admin hash from `/etc/motioneye/motion.conf` - Contains `@admin_password <SHA1_HASH>`.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Pass‑the‑hash admin auth due to accepting request signatures computed with password hashes... Admin access is accepted with hash‑based signatures.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Unsafe config restore that extracts attacker‑controlled tarballs into `CONF_PATH`... Upload a tar containing `lock_<id>` (or any action) as an executable. File is written into `CONF_PATH` by restore.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Unauthenticated action execution via `/action/<id>/<action>`... It executes `<action>_<camera_id>` found in `CONF_PATH` with `subprocess.Popen`.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qxvg-h7q2-hcxh
rules:
  - title: Detect motionEye RCE via Unauthenticated Action Execution
    description: Detects the creation of suspicious processes from the motionEye application, indicating successful Remote Code Execution (RCE) through the unauthenticated action execution vulnerability after an unsafe restore.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical multi-stage vulnerability chain in motionEye, affecting versions prior to 0.44.0, allows for unauthenticated remote code execution (RCE) under specific conditions. Attackers can exploit an arbitrary file read (Local File Inclusion or LFI) via the `picture/<id>/download` endpoint, specifically for local motion cameras, to extract sensitive configuration data like the admin password hash. This hash can then be used to forge authentication signatures, granting admin access without the plaintext password (a "pass-the-hash" technique). Subsequently, an unsafe configuration restore function, which extracts attacker-controlled tarballs into the `CONF_PATH` without proper sanitization, can be abused to drop malicious executables. Finally, an unauthenticated action execution endpoint allows for the immediate execution of these injected files, leading to full system compromise. This chain can be exploited unauthenticated if the normal user password is unset, or as an authenticated normal user to escalate to RCE.

## Attack Chain

1.  **Identify Local Camera ID**: The attacker first identifies or creates a local motion camera ID, which is a prerequisite for exploiting the vulnerable LFI path in `picture/<id>/download`.
2.  **Arbitrary File Read (LFI)**: The attacker sends a request to `/picture/<id>/download/<absolute_path>` (e.g., `/picture/1/download/%2Fetc%2Fhosts`) to read arbitrary files from the motionEye server's filesystem.
3.  **Extract Admin Hash**: Using the LFI, the attacker reads the motionEye configuration file (e.g., `/etc/motioneye/motion.conf`) to obtain the SHA1 hash of the `@admin_password`.
4.  **Achieve Admin Access**: The attacker computes a valid authentication signature for `/config/restore?_username=admin` using the stolen admin password hash as the key, bypassing standard authentication and gaining administrative privileges.
5.  **Upload Malicious Archive**: The attacker uploads a crafted tar archive containing an executable file named `lock_<id>` (or any valid action for a camera ID) via the now-accessible `/config/restore` endpoint. This executable is extracted into `CONF_PATH`.
6.  **Execute Malicious Action**: The attacker sends an unauthenticated POST request to `/action/<id>/lock`. The motionEye server executes the previously injected `lock_<id>` file via `subprocess.Popen`, resulting in remote code execution.
7.  **Impact**: The injected action creates a marker file `/tmp/meye_rce_ok`, confirming successful remote code execution.

## Impact

Successful exploitation of this vulnerability chain leads to critical consequences. If the normal user password is unset (a common default in some installations), an unauthenticated attacker can achieve full Remote Code Execution (RCE) on the motionEye server. If a normal user password is set, an authenticated normal user can escalate their privileges to admin and then achieve RCE. This allows for arbitrary file read on the server's filesystem and full compromise of the motionEye process account, potentially leading to data exfiltration, service disruption, or further network penetration. The impact in observed testing included creating arbitrary files on the filesystem.

## Recommendation

*   **Patch motionEye**: Immediately update all motionEye installations to version 0.44.0 or newer to address the vulnerabilities in `motioneye/motioneye/handlers/picture.py`, `motioneye/motioneye/mediafiles.py`, `motioneye/motioneye/handlers/base.py`, `motioneye/motioneye/config.py`, and `motioneye/motioneye/handlers/action.py`.
*   **Implement Rule `motioneye_rce_action_execution`**: Deploy the provided Sigma rule to detect suspicious process creation originating from the `motioneye` service account, indicating potential RCE.
*   **Review `CONF_PATH` Permissions**: Ensure that the `CONF_PATH` (typically `/etc/motioneye`) has restrictive write permissions, limiting write access only to the necessary motionEye process account.
*   **Regularly Review motionEye Logs**: Monitor `motioneye` service logs for unusual activity, especially for failed authentication attempts, unexpected file accesses, or process creations from the `motioneye` user.
