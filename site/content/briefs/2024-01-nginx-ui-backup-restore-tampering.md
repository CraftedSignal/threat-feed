---
title: nginx-ui Backup Restore Allows Tampering with Encrypted Backups
slug: 2024-01-nginx-ui-backup-restore-tampering
description: The nginx-ui backup restore mechanism allows attackers to tamper with encrypted backup archives and inject malicious configuration during restoration, potentially leading to arbitrary command execution.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - nginx-ui
  - backup-tampering
  - vulnerability
vendors:
  - nginx-ui
products:
  - nginx-ui
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-fhh2-gg7w-gwpq
rules:
  - title: Detect app.ini Modification in nginx-ui Backups
    description: Detects modification of the app.ini file within nginx-ui backups by looking for 'StartCmd' value changes, which can lead to command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect nginx-ui Backup Security Token Access
    description: Detects potential attempts to access the nginx-ui backup security token (Key and IV) by monitoring access to the .key file.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - linux
  - title: Detect nginx-ui restore.go vulnerability
    description: Detects anomalous process executions during backup restore operations indicative of the nginx-ui restore.go vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

The `nginx-ui` application, version v2.3.3 and earlier, contains a vulnerability in its backup and restore functionality. The backup format lacks a trusted integrity root, allowing attackers to manipulate encrypted backups. Specifically, the encryption key and initialization vector (IV) are provided to the client, and the integrity metadata (`hash_info.txt`) is encrypted using the same key. An attacker who obtains the backup security token can decrypt the archive, modify its contents, recalculate the integrity hashes, and re-encrypt the backup. The vulnerable code exists within `backup_crypto.go`, `backup.go`, `restore.go`, and `SystemRestoreContent.vue`. This vulnerability can be exploited in default Docker deployments.

## Attack Chain

1. An attacker gains access to the nginx-ui backup security token (Key and IV) through HTTP response headers or a `.key` file.
2. The attacker decrypts the `nginx-ui.zip` and `nginx.zip` archives using the obtained token and AES-256-CBC.
3. The attacker modifies the decrypted `app.ini` file within the extracted archive to inject malicious configuration, such as setting `StartCmd = bash`.
4. The attacker re-compresses the modified files into new `nginx-ui.zip` and `nginx.zip` archives.
5. The attacker calculates the SHA-256 hashes of the re-encrypted archive files.
6. The attacker updates the `hash_info.txt` file with the newly calculated SHA-256 hashes corresponding to the manipulated archives.
7. The attacker re-encrypts the modified archive and the `hash_info.txt` using the original Key and IV.
8. The attacker uploads the tampered backup to the `nginx-ui` restore interface, which accepts the malicious backup due to the lack of integrity verification. This results in the restoration of the attacker-controlled configuration and potential arbitrary command execution on the host.

## Impact

A successful attack allows an attacker to manipulate the `nginx-ui` application's configuration and internal state during the restoration process. This could lead to persistent configuration tampering, backdoor insertion into the nginx configuration, execution of attacker-controlled commands depending on the configuration settings, and potentially complete compromise of the `nginx-ui` instance. The severity is highly dependent on the restore permissions and the specific deployment configuration of `nginx-ui`.

## Recommendation

*   Deploy the patched version of nginx-ui (v2.3.4 or later) to remediate **CVE-2026-33026**.
*   Implement a trusted integrity root for backups. Integrity metadata must not be solely derived from data contained in the backup as described in the overview.
*   Enforce integrity verification in the restore operation to abort the process if hash verification fails, mitigating the tampering vulnerability detailed in the attack chain.
*   Monitor the `nginx-ui` application logs for any suspicious activity related to backup and restore operations, particularly those involving warnings related to hash mismatches as described in the PoC.
