---
title: Remote Code Execution in LibreNMS Signal Alert Transport Module
slug: 2026-08-librenms-rce
description: An authenticated administrator can execute arbitrary code on LibreNMS servers by injecting commands into the Signal Alert Transport configuration fields, triggering unsafe system exec calls.
date: "2026-08-18T20:58:00Z"
lastmod: "2026-08-19T02:55:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - librenms
vendors:
  - LibreNMS
products:
  - LibreNMS (21.6.0 - 26.4.x)
  - LibreNMS (< 26.7.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability is caused by an unsafe exec call in deliverAlert function of LibreNMS/Alert/Transport/Signal.php.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated administrator can configure a malicious URL for the Oxidized integration, allowing the attacker to inject arbitrary HTML and JavaScript into the device showconfig page.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The Oxidized integration URL (oxidized.url) is admin-configurable. LibreNMS fetches device info and version history from that URL and renders JSON fields into HTML without htmlspecialchars().
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-c9fv-cgmm-2wg7
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade LibreNMS to 26.5.0 or later
      owner: IT Operations
      due: 48h
      evidence: Source provides affected versions and patch availability.
  mitigation_plan:
    - priority: immediate
      action: Audit administrative alert transport configurations for malicious input
      owner: SOC
      addresses: CVE-2026-55182
      evidence: PoC demonstrates injection via Alert Transport fields.
updates:
  - at: "2026-08-19T02:55:50Z"
    level: L2
    summary: added coverage for LibreNMS (< 26.7.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-7gww-x7fh-jf9j
---

LibreNMS versions 21.6.0 through 26.4.x are vulnerable to a remote code execution (RCE) vulnerability (CVE-2026-55182) within the Signal Alert Transport module. The vulnerability stems from insufficient sanitization of user-provided input in the `deliverAlert` function located in `LibreNMS/Alert/Transport/Signal.php`. An authenticated administrative user can manipulate the 'Path' and 'Recipient' fields in the Alert Transport configuration to perform command injection. These inputs are passed to an unsafe `exec` call, which is further exacerbated by the `scripts/composer_wrapper.php` script that accepts and executes these malicious arguments. By chaining these weaknesses, an attacker with existing administrative access can execute arbitrary commands on the underlying host server, leading to potential full system compromise.

## Attack Chain

1. Attacker authenticates to the LibreNMS web interface with administrative privileges.
2. Attacker navigates to the 'Alert Transports' configuration menu.
3. Attacker creates a new 'Signal' type alert transport.
4. Attacker modifies the 'Path' configuration field to target `../scripts/composer_wrapper.php`.
5. Attacker injects a command sequence starting and ending with a semicolon (`;`) into the 'Recipient' field.
6. Attacker saves the transport configuration.
7. Attacker triggers the vulnerability by clicking the 'Test Transport' button associated with the malicious entry.
8. The application executes the injected command via the vulnerable `exec` call within the backend script, resulting in RCE.

## Impact

Successful exploitation of CVE-2026-55182 allows an authenticated attacker to achieve full remote code execution on the server hosting the LibreNMS application. This grants the attacker the ability to execute arbitrary commands with the privileges of the web service user, which can lead to data exfiltration, modification of system configurations, or lateral movement into the wider internal network. Given LibreNMS is typically deployed to monitor network infrastructure, this exposure could provide an attacker with significant visibility and control over managed network devices.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Upgrade all instances of LibreNMS to version 26.5.0 or later to include the vendor patch for CVE-2026-55182.
- Review administrative user accounts for unauthorized activity or creation of new alert transports.
- Deploy server-side auditing to monitor for unexpected child processes spawned by the web service user (e.g., `apache`, `www-data`, `nginx`).
- Restrict the ability of the web service user to execute system-level binaries via sudo or system policies.
- Monitor logs for the execution of `composer_wrapper.php` containing unusual characters in arguments, such as semicolons or shell operators.
