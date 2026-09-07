---
title: Arbitrary File Upload and RCE in Lara Dashboard
slug: 2026-09-lara-dashboard-rce
description: Lara Dashboard versions prior to 1.3.2 are vulnerable to arbitrary file upload via the core-upgrades endpoint, allowing unauthorized administrators to achieve remote code execution.
date: "2026-09-07T23:37:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - rce
  - file-upload
products:
  - Lara Dashboard (< 1.3.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Lara Dashboard before 1.3.2 authorizes the POST /admin/settings/core-upgrades/upload endpoint with only the settings.edit permission.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can upload a malicious archive containing modified application files such as routes/web.php with embedded system commands.
    confidence_band: high
cves:
  - id: CVE-2026-86437
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86437
rules:
  - title: Detects CVE-2026-86437 Exploitation - Malicious POST to core-upgrades
    description: Detects unauthorized attempts to access the core-upgrades upload endpoint; while authorization logic occurs within the application, monitor requests to this endpoint for anomalies.
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
    - action: Upgrade Lara Dashboard to version 1.3.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Lara Dashboard before 1.3.2 authorizes the POST /admin/settings/core-upgrades/upload endpoint incorrectly.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Lara Dashboard to version 1.3.2.
      owner: IT Operations
      addresses: CVE-2026-86437
      evidence: NVD vulnerability report
---

Lara Dashboard versions before 1.3.2 contain an authorization flaw in the /admin/settings/core-upgrades/upload endpoint. The application incorrectly restricts access to this endpoint to the 'settings.edit' permission rather than enforcing 'Superadmin' status. This vulnerability allows an authenticated administrator with limited permissions to upload and extract arbitrary ZIP archives. By crafting a malicious archive, an attacker can overwrite critical application files, such as 'routes/web.php', with payloads containing system commands. These commands execute in the context of the web server user, providing the attacker with full control over the application environment, including access to database credentials and environment secrets. This attack allows for persistence and full system compromise, impacting the confidentiality, integrity, and availability of the host application.

## Attack Chain

1. Attacker authenticates to the Lara Dashboard using valid administrative credentials that possess the 'settings.edit' permission.
2. Attacker navigates to the core-upgrades administrative panel within the dashboard interface.
3. Attacker crafts a malicious ZIP archive containing weaponized PHP files designed to overwrite existing application source code.
4. Attacker performs an HTTP POST request to '/admin/settings/core-upgrades/upload' containing the malicious ZIP archive.
5. The application validates the 'settings.edit' permission and proceeds to extract the archive to the web application's root directory.
6. The uploaded malicious PHP files overwrite legitimate application source code, such as 'routes/web.php'.
7. Attacker triggers the execution of the injected code by requesting the modified PHP file via a browser or script.
8. Arbitrary system commands are executed with the privileges of the web server user, resulting in credential exfiltration or full system compromise.

## Impact

Successful exploitation leads to full remote code execution, enabling attackers to extract sensitive environment secrets, access database credentials, and gain persistence on the server. The target is the Lara Dashboard application, specifically affecting installations prior to version 1.3.2.

## Recommendation

Prioritize the upgrade of all Lara Dashboard instances to version 1.3.2 or later to address the insufficient authorization check on the file upload endpoint.
