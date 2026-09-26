---
title: Arbitrary File Deletion in Froxlor via Symlink Following
slug: 2026-09-froxlor-symlink-deletion
description: Froxlor versions through 2.3.10 are vulnerable to arbitrary file deletion where authenticated users can plant symlinks to trigger recursive deletion by a root-privileged cron task, leading to potential data destruction.
date: "2026-09-26T14:59:41Z"
lastmod: "2026-09-26T15:14:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:froxlor:froxlor:*:*:*:*:*:*:*:*
tags:
  - information-disclosure
  - api-security
  - credential-access
  - authentication-bypass
  - vulnerability
  - webserver
  - web-vulnerability
  - authorization-bypass
  - spoofing
vendors:
  - Froxlor
products:
  - Froxlor (<= 2.3.10)
  - Froxlor (< 2.3.13)
  - froxlor (< 2.3.12)
  - Froxlor (2.0.0-2.3.10)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: An authenticated customer who can write to the FTP home directory can plant a symlink between task insertion and cron execution, causing the root cron job to recursively delete arbitrary directory trees.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The root cron job to recursively delete arbitrary directory trees, resulting in cross-tenant data destruction and host denial of service.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated low-privilege customer with subdomain-create rights can supply a subdomain redirect URL that carries a CR/LF payload... allowing the attacker to break out of the emitted directive and inject arbitrary web-server configuration lines.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: froxlor regenerates and reloads the web-server configuration as root, so the injected directives take effect server-wide.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Froxlor before 2.3.13 returns the ssl_key_file column — which stores the raw PEM TLS private-key content — verbatim in the JSON responses of the Certificates.get and Certificates.listing API commands.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers holding hijacked sessions, valid API keys, or 2FA trust tokens retain full account access after password rotation.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: This creates a bypass between the UI/administrator configuration and the API, and allows a customer to authorize sender identities outside their hosted domains.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated low-privileged customer can upload a malicious SSL certificate containing an unsanitized issuer organization field.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This crosses a privilege boundary from customer to admin and can result in full administrator account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-100715
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100715
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100717
  - https://github.com/Froxlor/Froxlor/security/advisories/GHSA-c3p2
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100708
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100711
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100713
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100718
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100720
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Froxlor to version 2.3.12 or later.
      owner: IT Operations
      due: 24h
      evidence: This issue is fixed in Froxlor 2.3.12.
  mitigation_plan:
    - priority: immediate
      action: Review cron task schedules and restrict permissions of user-writeable directories.
      owner: System Administration
      addresses: CVE-2026-100715
      evidence: Froxlor through 2.3.10 is vulnerable to arbitrary file deletion via symlink following in the FTP data deletion cron task.
updates:
  - at: "2026-09-26T15:13:38Z"
    level: L2
    summary: added coverage for Froxlor (< 2.3.13)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100708
  - at: "2026-09-26T15:13:52Z"
    level: L2
    summary: added coverage for froxlor (< 2.3.12)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100711
  - at: "2026-09-26T15:14:00Z"
    level: L2
    summary: added coverage for Froxlor (<= 2.3.10)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100713
  - at: "2026-09-26T15:14:08Z"
    level: L2
    summary: added coverage for Froxlor (<= 2.3.10)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100718
  - at: "2026-09-26T15:14:15Z"
    level: L2
    summary: added coverage for Froxlor (2.0.0-2.3.10)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100720
---

Froxlor versions through 2.3.10 contain a critical vulnerability in the deleteFtpData cron task (Task 8). When an FTP account is deleted, the application queues this task to clean up associated data. The task execution flow invokes FileDir::makeCorrectDir() without the $fixed_homedir argument, causing the system to skip necessary symlink component path walking. Subsequently, the application executes a recursive 'rm -rf' operation with root privileges on the resulting path. 

Because the application appends a trailing slash to the path before execution, the underlying GNU rm utility is forced to dereference symlinks. An authenticated user with write access to their designated FTP home directory can place a symbolic link in the target path after the task is queued but before the cron job executes. This allows the attacker to redirect the recursive deletion operation to arbitrary directories on the host filesystem, resulting in cross-tenant data loss and host-level denial of service. This vulnerability is addressed in Froxlor version 2.3.12.

## Attack Chain

1. Attacker obtains authenticated access to an FTP account managed by the target Froxlor instance.
2. Attacker initiates the deletion of their own FTP account via the Froxlor interface, triggering the scheduling of the deleteFtpData cron task.
3. Attacker identifies the target path that will be processed by the upcoming root-privileged cron cleanup job.
4. Attacker plants a symbolic link pointing to a critical system directory (e.g., /etc or a peer tenant's data directory) within the expected FTP home path.
5. The system root user executes the scheduled cron task, which resolves the path containing the attacker-controlled symlink.
6. The 'rm -rf' command dereferences the symlink and recursively deletes the contents of the target directory.
7. Final impact is realized as system instability, data loss, or total host denial of service.

## Impact

Successful exploitation allows an authenticated customer to perform arbitrary file deletion with root privileges. This can result in the destruction of cross-tenant data, the deletion of critical system configuration files, or a complete host denial of service. Given the broad permissions of the cron task, the potential for widespread data corruption is significant.

## Recommendation

Prioritize the update of all Froxlor installations to version 2.3.12 or later to include the patch for CVE-2026-100715. For environments that cannot be patched immediately, restrict user access to FTP home directories and audit the filesystem for unexpected symbolic links located within directories managed by Froxlor's cleanup cron tasks. Ensure that file system auditing is enabled to track 'rm' executions by the root user that target directories outside of expected user homedirs.
