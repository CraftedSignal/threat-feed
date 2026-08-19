---
title: Grav .htaccess Case-Insensitive Extension Bypass
slug: 2026-08-grav-htaccess-bypass
description: A misconfigured .htaccess file in Grav allows unauthenticated remote attackers to bypass access restrictions and download sensitive configuration and source files by utilizing uppercase file extensions on case-insensitive filesystems.
date: "2026-08-19T22:33:31Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Grav
products:
  - Grav (2.0.1)
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows unauthenticated remote attackers to access sensitive files by bypassing .htaccess restrictions.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The bypass relies on the case-insensitivity characteristic common in Windows-based filesystems.
    confidence_band: med
cves:
  - id: CVE-2026-62673
references:
  - https://github.com/advisories/GHSA-vwg3-w8w3-pc79
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62673
rules:
  - title: Detect CVE-2026-62673 Exploitation - Unauthorized Access to Sensitive Grav Files
    description: Detects potential exploitation of CVE-2026-62673 by identifying successful HTTP 200 responses for sensitive file types in restricted directories, specifically where the request URI contains uppercase extensions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Deploy updated .htaccess rules or update to Grav 2.0.4
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-62673 fix
  hunt_leads:
    - lead: Search web logs for 200 responses to sensitive extensions in /user/ or /system/ directories
      technique_id: T1190
      data_needed:
        - webserver_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source describes vulnerability as leading to information disclosure
  mitigation_plan:
    - priority: immediate
      action: Patch web server configuration
      owner: IT Operations
      addresses: CVE-2026-62673
      evidence: Vendor advisory
---

Grav CMS (v2.0.1 and earlier) utilizes an `.htaccess` file to restrict access to sensitive file types stored within the `user/` and `system/vendor/` directories. These directives are intended to return a 403 Forbidden status for requests targeting files with extensions such as `.yaml`, `.json`, and `.php`. However, the current configuration rules lack the `[NC]` (No Case) Apache directive flag. 

On case-insensitive filesystems, such as NTFS (Windows) or HFS+ (macOS), the operating system resolves uppercase extensions to the same file path as their lowercase counterparts, but the web server fails to match the blocking rule. Consequently, an attacker can access sensitive data by requesting files with uppercase extensions (e.g., `.YAML` instead of `.yaml`). This can lead to the exposure of API keys, administrative credentials, and application source code, depending on the server configuration. The vulnerability is mitigated on native Linux distributions utilizing case-sensitive filesystems like ext4.

## Impact

The vulnerability results in unauthorized information disclosure of critical configuration and source files. Attackers can exfiltrate sensitive plugin data (including API keys), system configuration files (`system.yaml`), and potentially source code if the server is configured to serve `.PHP` files as static content rather than executing them. This impacts any Grav instance deployed on Windows, macOS, or Docker environments with volumes mounted from these systems.

## Recommendation

- Immediately update to Grav version 2.0.4 or later where the missing `[NC]` flags have been applied to the rewrite rules.
- If immediate patching is not possible, manually edit the root `.htaccess` file to append the `[NC]` flag to the relevant `RewriteRule` definitions on lines 68, 70, and 72.
- Review Apache web server logs for HTTP 200 responses to requests targeting sensitive file types with non-standard capitalization, specifically focusing on `user/` and `system/vendor/` URI paths.
- Audit infrastructure deployments to ensure that web-facing sensitive directories are not hosted on case-insensitive volumes.
