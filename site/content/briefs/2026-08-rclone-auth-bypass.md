---
title: Authorization Bypass in rclone serve restic --private-repos
slug: 2026-08-rclone-auth-bypass
description: An authorization bypass vulnerability in rclone's restic server allows authenticated users to access and manipulate repositories of other users via path traversal, impacting multi-tenant environments using backend storage that canonicalizes path segments.
date: "2026-08-05T21:25:39Z"
lastmod: "2026-08-06T15:22:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rclone:rclone:*:*:*:*:*:*:*:*
vendors:
  - rclone
products:
  - rclone (1.74.3)
  - rclone
affected_os:
  - linux
  - windows
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The rclone 'serve restic' command, when configured with the '--private-repos' flag, suffers from an authorization bypass vulnerability due to a path traversal flaw.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Any authenticated user can read... the victim's restic config and keys/* files.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker-controlled filename can therefore terminate the intended path literal and append PowerShell statements executed as the victim's SSH account.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This yields arbitrary file write as the victim user, e.g. overwriting ~/.ssh/authorized_keys... i.e. code execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1006
    technique_name: Direct Volume Access
    evidence: The primary vulnerable component is the backend-independent WithRemote middleware... it accepts a leading parent component and stores that unsafe relative path.
    confidence_band: high
cves:
  - id: CVE-2026-54572
    cvss: 7.5
    epss: 0.00309
  - id: CVE-2026-71309
  - id: CVE-2026-71312
    cvss: 8
references:
  - https://github.com/advisories/GHSA-fqj9-69pf-6pjg
  - https://github.com/advisories/GHSA-2m8m-jhrm-w6j2
  - https://github.com/advisories/GHSA-cf44-9pgv-m4xc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54572
  - https://github.com/advisories/GHSA-45pq-889g-fcgh
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-71309
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2679
rules:
  - title: Detect rclone Process Executing PowerShell
    description: Detects rclone invoking PowerShell, which may indicate exploitation of CVE-2026-71312 when rclone is used with SFTP remotes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit and patch all instances of rclone 1.74.3 utilizing --private-repos.
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends this as the primary resolution.
  hunt_leads:
    - lead: Search web/proxy logs for HTTP requests containing '..' or '%2e%2e' patterns in the URI path directed at rclone restic endpoints.
      technique_id: T1190
      data_needed:
        - web_server_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The bypass relies on sending '..' in the URL path.
updates:
  - at: "2026-08-05T21:25:50Z"
    level: L2
    summary: 'added detection rule: Detect rclone Process Executing PowerShell'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-2m8m-jhrm-w6j2
  - at: "2026-08-05T21:25:58Z"
    level: L2
    summary: added coverage for rclone
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-cf44-9pgv-m4xc
  - at: "2026-08-05T21:26:05Z"
    level: L2
    summary: added coverage for rclone
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-45pq-889g-fcgh
  - at: "2026-08-06T15:22:14Z"
    level: L2
    summary: added CVE-2026-54572 +2
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2679
---

The rclone `serve restic` command includes a `--private-repos` feature intended to provide multi-tenant isolation by restricting users to their own path prefix (e.g., `/<username>/`). This security boundary is enforced by two separate chi middlewares that handle request authorization and object path resolution differently. The `checkPrivate` middleware validates that the authenticated user matches the initial path segment. However, the `WithRemote` middleware constructs the backend object key using the raw, un-cleaned URL path.

An authenticated user can bypass this confinement by sending a request with a traversal sequence, such as `GET /<attacker>/../<victim>/config`. Because the path starts with the attacker's username, the authorization middleware permits the request. However, backends that use POSIX `path.Clean` semantics (including the common `sftp`, `ftp`, and `memory` backends) resolve the `..` segment, directing the operation to the victim's repository. This vulnerability enables unauthorized reading, overwriting, or deletion of another tenant's backup metadata and blobs. The vulnerability affects rclone version 1.74.3.

## Attack Chain

1. Attacker establishes a valid, low-privileged authenticated session on the target rclone instance configured with `--private-repos`.
2. Attacker crafts a malicious HTTP request using path traversal sequences, targeting a victim's repository path (e.g., `/mallory/../alice/config`).
3. The `checkPrivate` middleware observes the initial path segment (`mallory`) and confirms it matches the authenticated session user, allowing the request to proceed.
4. The `WithRemote` middleware captures the un-cleaned URL path `mallory/../alice/config` and passes it as the remote key to the storage backend.
5. The storage backend (e.g., SFTP/FTP) invokes POSIX path normalization, collapsing `mallory/../alice/config` into `alice/config`.
6. The backend handler executes the requested operation (GET, POST, or DELETE) against the victim's resource.
7. Attacker successfully exfiltrates metadata/blobs, poisons the repository, or deletes the victim's backups.

## Impact

Successful exploitation results in a total loss of confidentiality, integrity, and availability for the victim's restic repository on the affected server. Attackers can read sensitive restic `config` and `keys` metadata, poison existing backups by overwriting objects, or delete the entire repository. This vulnerability effectively nullifies the multi-tenant isolation provided by the `--private-repos` flag. The impact is critical for hosting providers or organizations sharing a single rclone restic server among multiple users.

## Recommendation

Prioritize the following actions to secure rclone instances:
- Upgrade rclone to the latest patched version addressing this bypass, or disable the `--private-repos` flag until an update is applied.
- Audit existing multi-tenant rclone deployments to identify those utilizing the `--private-repos` flag with backends like SFTP or FTP.
- Implement network-level access controls or proxy-based URL path normalization to reject requests containing `..` or `%2e%2e` sequences before they reach the rclone server.
- Use backends that do not rely on implicit POSIX path normalization if available, or isolate multi-tenant backup repositories at the infrastructure level rather than relying on application-layer flags.
