---
title: Arbitrary Command Execution in Snipe-IT Backup Restoration
slug: 2026-09-snipe-it-rce
description: Snipe-IT versions prior to 8.7.0 are vulnerable to OS command injection when a superadministrator restores a crafted backup archive, allowing arbitrary command execution via the MySQL client.
date: "2026-09-08T17:45:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:snipeitapp:snipe-it:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - cve
  - vulnerability
vendors:
  - Snipe-IT
products:
  - Snipe-IT (< 8.7.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An authenticated superadministrator who uploads a crafted ZIP backup... can execute arbitrary OS commands.
    confidence_band: high
cves:
  - id: CVE-2026-86733
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86733
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Snipe-IT to 8.7.0
      owner: IT Operations
      due: 24h
      evidence: Vendor patch availability
  mitigation_plan:
    - priority: immediate
      action: Set DB_SANITIZE_BY_DEFAULT to true
      owner: IT Operations
      addresses: CVE-2026-86733
      evidence: Configuration mitigates lack of sanitizer parameter
---

Snipe-IT versions before 8.7.0 contain a critical vulnerability (CVE-2026-86733) that allows an authenticated superadministrator to achieve arbitrary operating-system command execution. The vulnerability exists within the backup restoration process, where the application streams SQL content from an uploaded backup archive directly into the `mysql` or `mariadb` command-line client. Because the client is invoked without the `--binary-mode` flag, it interprets sequences starting with backslashes as local shell commands. An attacker with superadministrator privileges can supply a malicious ZIP archive containing a crafted SQL file to the `/admin/backups/upload` endpoint and trigger a restore via `POST /admin/backups/restore/{filename}`. If the `clean` sanitizer parameter is omitted, which is the default configuration unless `DB_SANITIZE_BY_DEFAULT` is enabled, the embedded shell directives are executed by the underlying operating system user running the web application. This leads to full system compromise, including the exfiltration of application secrets like `APP_KEY` and database credentials.

## Impact

Successful exploitation allows a malicious superadministrator to execute arbitrary commands on the server hosting the Snipe-IT application. This results in the complete loss of confidentiality, integrity, and availability of the application, including access to database content, environment configuration, and potential lateral movement from the host system.

## Recommendation

1. Upgrade Snipe-IT to version 8.7.0 or later immediately.
2. If an immediate upgrade is not possible, ensure the `DB_SANITIZE_BY_DEFAULT` configuration parameter is set to `true` to force sanitization during backup restoration.
3. Restrict access to the superadministrator role to trusted personnel only, as exploitation requires high-level administrative access.
4. Audit logs for `POST` requests to `/admin/backups/upload` and `/admin/backups/restore/` to identify anomalous administrative behavior.
