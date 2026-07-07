---
title: Incus S3 Multipart Upload Path Traversal Leading to RCE (CVE-2026-48753)
slug: 2026-07-incus-s3-path-traversal-rce
description: The Incus `incusd` daemon, specifically its S3 protocol multipart upload endpoint in versions prior to 7.1.0, is vulnerable to CVE-2026-48753, a critical path traversal flaw via the `uploadId` parameter, enabling unauthenticated attackers to write arbitrary files to any location on the host system, which can be leveraged for persistent arbitrary command execution.
date: "2026-07-03T10:36:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - rce
  - incus
  - s3
  - linux
  - vulnerability
vendors:
  - Incus
products:
  - incusd < 7.1.0
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The S3 protocol upload endpoint is vulnerable to path traversal and allows creation of arbitrary files on the host.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This behavior could lead to arbitrary command execution... `cmd='id > /incus-s3-uploadid-bash-rce; rm -f $target'`
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: ""
    evidence: arbitrary file write... by writing a malicious entry to `/etc/cron.d`, leading to persistent code execution
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-ccjc-4qc3-jxqc
rules:
  - title: Detects CVE-2026-48753 Exploitation - Incus S3 Path Traversal RCE Attempt
    description: Detects exploitation attempts of CVE-2026-48753, where an attacker leverages a path traversal vulnerability in Incus's S3 multipart upload via a crafted uploadId query parameter to achieve arbitrary file write and potential RCE.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical path traversal vulnerability, tracked as CVE-2026-48753, has been identified in the Incus `incusd` daemon affecting versions prior to 7.1.0. This flaw resides within the S3 protocol's multipart upload endpoint, specifically in the handling of the `uploadId` parameter. Attackers can leverage this unsanitized parameter to inject path traversal sequences (e.g., `../../`) and write arbitrary files to sensitive locations on the host system. This arbitrary file write capability can be escalated to achieve persistent arbitrary command execution, for instance, by creating malicious cron jobs in `/etc/cron.d`. The successful exploitation of this vulnerability would grant an unauthenticated attacker the ability to execute commands with the privileges of the Incus service, posing a significant risk of full system compromise for affected Linux deployments utilizing Incus's S3 functionality.

## Attack Chain

1.  Attacker identifies a vulnerable Incus instance (version < 7.1.0) with an exposed S3 API, typically via `incus config set core.storage_buckets_address`.
2.  The attacker crafts a multipart S3 `PUT` request, targeting an S3 bucket configured on the vulnerable Incus instance.
3.  The `uploadId` query parameter within the `PUT` request is maliciously manipulated, containing path traversal sequences such as `../../../../etc/cron.d`.
4.  The request body is populated with the content of a malicious cron job entry, for example, `* * * * * root /bin/sh -c 'id > /incus-s3-uploadid-bash-rce; rm -f /etc/cron.d/part-00001'`.
5.  Due to the vulnerability in `internal/server/storage/s3/local/multipart.go`, Incus concatenates the unsanitized `uploadId` directly into the target file path during the upload process.
6.  This results in an arbitrary file write on the host system, placing the malicious cron job content into a file like `/etc/cron.d/part-00001`.
7.  The system's cron daemon periodically executes entries found in `/etc/cron.d`, triggering the newly created malicious job, leading to arbitrary command execution (e.g., `id > /incus-s3-uploadid-bash-rce`).
8.  The executed cron job also includes a command to delete itself (`rm -f /etc/cron.d/part-00001`), providing persistent remote code execution while attempting to remove forensic evidence.

## Impact

The primary impact of CVE-2026-48753 is the ability for an unauthenticated attacker to achieve arbitrary file write on the host system where Incus is running. This directly enables arbitrary command execution, as demonstrated by the ability to install persistent cron jobs. Successful exploitation can lead to a complete compromise of the Incus host, allowing attackers to establish persistence, exfiltrate data, disrupt services, or pivot to other systems within the network. This vulnerability is critical due to its unauthenticated nature and the severe consequences of command execution.

## Recommendation

*   **Patch CVE-2026-48753 immediately** by upgrading your Incus installation to version 7.1.0 or later as advised by the advisory.
*   **Deploy the Sigma rule in this brief** to your SIEM/EDR to detect exploitation attempts of CVE-2026-48753 by monitoring for suspicious S3 PUT requests.
*   **Monitor web server access logs** for HTTP PUT requests to S3 endpoints that contain path traversal sequences (`../../` or `..%2F..%2F`) in the `uploadId` query parameter.
*   **Enable comprehensive file integrity monitoring** for critical system directories like `/etc/cron.d`, `/tmp`, and other common locations for malicious file drops.
