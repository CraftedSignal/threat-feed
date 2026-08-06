---
title: Arbitrary File Deletion Vulnerability in WordPress File Manager Plugin
slug: 2026-08-file-manager-plugin-rce
description: The WordPress File Manager plugin (versions 6.0-6.9) contains an arbitrary file deletion vulnerability allowing authenticated attackers to delete critical server files and achieve remote code execution.
date: "2026-08-06T05:21:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - wordpress
  - remote-code-execution
  - arbitrary-file-deletion
vendors:
  - WordPress
products:
  - File Manager (6.0-6.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The File Manager plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the connector function.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This makes it possible for authenticated attackers to delete arbitrary files on the server, which can lead to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-15991
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15991
rules:
  - title: Detects CVE-2026-15991 Exploitation - Arbitrary File Deletion Attempt
    description: Detects exploitation attempts against the WordPress File Manager plugin by identifying suspicious cmd or cmf parameters in POST requests.
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update WordPress File Manager plugin to a version > 6.9
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-15991 vulnerability range 6.0-6.9
  hunt_leads:
    - lead: Search web logs for POST requests containing cmd=rm or cmf=file
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: NVD advisory description of exploitation method
  mitigation_plan:
    - priority: immediate
      action: Patch plugin
      owner: IT Operations
      addresses: CVE-2026-15991
      evidence: NVD advisory
---

The File Manager plugin for WordPress (versions 6.0 through 6.9) is vulnerable to an arbitrary file deletion flaw caused by insufficient path validation within its connector function. The vulnerability arises from a discrepancy between how the elFinder library processes request parameters for permission handlers versus command dispatching. Authenticated users with subscriber-level access can manipulate the request by utilizing a POST request with specific cmd or cmf parameters. Because the library's bind registration ignores these commands while the dispatcher processes them using the merged $_GET and $_POST superglobals, an attacker can bypass security controls to target files relative to the WordPress ABSPATH. The ability to delete critical files such as wp-config.php can facilitate a subsequent remote code execution (RCE) attack, making this a high-impact vulnerability for WordPress environments.

## Impact

Successful exploitation allows an authenticated attacker to delete arbitrary files on the underlying web server, potentially compromising the integrity and availability of the WordPress site. By deleting key configuration files like wp-config.php, an attacker can trigger a re-installation process or intercept database credentials, leading to full server compromise and RCE. This vulnerability affects any WordPress instance running the File Manager plugin between versions 6.0 and 6.9.

## Recommendation

* Update the File Manager plugin for WordPress to the latest available version immediately to remediate the path validation logic.
* Monitor web access logs for POST requests to the file manager connector endpoint containing suspicious query parameters such as cmd=rm or cmf=file.
* Audit user roles within WordPress to ensure unauthorized users do not possess subscriber-level access or higher if not strictly required for site operation.
