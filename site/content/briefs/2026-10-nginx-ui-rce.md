---
title: Authenticated Remote Code Execution in Nginx-UI via Backup Restoration
slug: 2026-10-nginx-ui-rce
description: An authenticated user can achieve remote code execution in Nginx-UI by uploading a maliciously crafted backup file that overwrites application configuration settings.
date: "2026-10-09T21:23:28Z"
lastmod: "2026-10-09T21:28:05Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - remote-code-execution
  - cve-2026-107806
  - nginx-ui
  - vulnerability
  - authentication-bypass
  - cve-2026-107808
  - web-application
  - n8n
  - csrf
  - cve-2026-107809
vendors:
  - Nginx-UI
products:
  - Nginx-UI (1.9.10-0.20260421071512-7864e378f5cf to < 1.9.10-0.20260728074146-a467ed652591)
  - Nginx-UI (>= 1.9.10-0.20250517140552-daee3ac7ade1, < 1.9.10-0.20260728074558-95cd21b70814)
  - Nginx-UI (>= 1.9.10-0.20250517140552-daee3ac7ade1, < 1.9.10-0.20260728074433-a3999bd78a3b)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: By setting nginx command fields in the restored app.ini, the attacker can execute commands in the nginx-ui runtime context.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An attacker who obtains the password gains full access despite the registered security key.
    confidence_band: high
cves:
  - id: CVE-2026-107806
references:
  - https://github.com/advisories/GHSA-p393-cf76-4jmr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107806
  - https://github.com/advisories/GHSA-45gv-9wjv-xh7p
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107808
  - https://github.com/advisories/GHSA-33rr-wq23-g6gg
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107809
rules:
  - title: Detect Nginx-UI Backup Restoration Attempt
    description: Detects exploitation of CVE-2026-107806 via POST requests to the /api/restore endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
  - title: Detects CVE-2026-107809 Exploitation - CSRF Attempt Against Nginx-UI API
    description: Detects potential CSRF attempts where a POST/PUT/DELETE request to sensitive Nginx-UI endpoints occurs without a valid Origin or Referer header matching the expected application host.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Nginx-UI to 1.9.10-0.20260728074146-a467ed652591 or later.
      owner: IT Operations
      due: 24h
      evidence: Nginx-UI patch for CVE-2026-107806.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /api/restore and /api/nginx/test endpoints.
      owner: IT Operations
      addresses: CVE-2026-107806
      evidence: Source analysis of vulnerable endpoints.
updates:
  - at: "2026-10-09T21:27:55Z"
    level: L2
    summary: added coverage for Nginx-UI (>= 1.9.10-0.20250517140552-daee3ac7ade1, < 1.9.10-0.20260728074558-95cd21b70814)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-45gv-9wjv-xh7p
  - at: "2026-10-09T21:28:05Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-107809 Exploitation - CSRF Attempt Against Nginx-UI API'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-33rr-wq23-g6gg
---

Nginx-UI is susceptible to a critical authenticated remote code execution (RCE) vulnerability, tracked as CVE-2026-107806. The issue resides in the backup restoration feature, specifically within the `POST /api/restore` endpoint. An authenticated user can bypass configuration security constraints by providing a forged backup file. The application fails to strictly validate the contents of the restored backup, allowing an attacker to modify `app.ini`. By injecting arbitrary commands into the `TestConfigCmd` field within this configuration file, an attacker can trigger command execution via the `POST /api/nginx/test` endpoint. This vulnerability allows an attacker to achieve full control over the runtime environment of the Nginx-UI service, potentially leading to unauthorized data access and persistence within the underlying system. This was identified in Nginx-UI versions between 1.9.10-0.20260421071512-7864e378f5cf and 1.9.10-0.20260728074146-a467ed652591.

## Attack Chain

1. Attacker authenticates to the target Nginx-UI instance and obtains a valid JWT.
2. Attacker initiates an authorized backup request to `GET /api/backup` to retrieve current encrypted backup artifacts and the required `X-Backup-Security` token.
3. Attacker decrypts the retrieved backup archive using the extracted security token and IV.
4. Attacker modifies the `app.ini` file within the decrypted archive to include a malicious payload in the `TestConfigCmd` setting.
5. Attacker re-encrypts the modified backup archive and regenerates the manifest signature using the same HMAC key derivation logic.
6. Attacker uploads the forged backup via `POST /api/restore` with the malicious payload included.
7. Attacker invokes `POST /api/nginx/test` to force the application to execute the modified `TestConfigCmd`.
8. Arbitrary code executes within the Nginx-UI container context, completing the exploit chain.

## Impact

Successful exploitation results in full command execution within the Nginx-UI runtime environment. An attacker can use this access to read or modify sensitive configuration data, extract JWT secrets, corrupt application state, or move laterally within the host environment, depending on the container's privileges and host integration.

## Recommendation

Prioritized actions for detection and mitigation:

- Patch Nginx-UI to version 1.9.10-0.20260728074146-a467ed652591 or later to remediate CVE-2026-107806.
- Deploy WAF or web server rules to audit or block `POST` requests to `/api/restore` and `/api/nginx/test` originating from non-administrative user accounts.
- Monitor logs for unusual configuration changes, specifically modifications to `app.ini` or attempts to trigger nginx test command execution from suspicious user sessions.
- Restrict access to the Nginx-UI interface to trusted internal networks only to minimize the exposure of administrative endpoints.
