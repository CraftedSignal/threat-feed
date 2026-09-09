---
title: Local File Inclusion in Eventin WordPress Plugin
slug: 2026-09-eventin-lfi
description: The Eventin WordPress plugin contains a local file inclusion vulnerability in the event_layout parameter, allowing authenticated contributors to execute arbitrary PHP code.
date: "2026-09-09T03:51:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:themewinter:eventin:*:*:*:*:*:*:*:*
tags:
  - lfi
  - vulnerability
  - wordpress
  - webserver
vendors:
  - Themewinter
products:
  - Eventin (<= 4.1.22)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for authenticated attackers... to include and execute arbitrary .php files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-15667
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15667
rules:
  - title: Detects CVE-2026-15667 Exploitation - LFI via Eventin REST API
    description: Detects suspicious REST API requests to the Eventin plugin where the event_layout parameter contains path traversal sequences indicative of LFI exploitation.
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
    - action: Upgrade Eventin plugin to version > 4.1.22
      owner: IT Operations
      due: 48h
      evidence: Source specifies version 4.1.22 and earlier are vulnerable
  hunt_leads:
    - lead: Search logs for REST API requests containing 'event_layout' and path traversal patterns
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies event_layout as the injection point
  mitigation_plan:
    - priority: immediate
      action: Remove Contributor role permissions for the Eventin plugin
      owner: IT Operations
      addresses: CVE-2026-15667
      evidence: Source confirms contributor-level access can perform the exploit
---

The Eventin WordPress plugin (versions 4.1.22 and earlier) contains a Local File Inclusion (LFI) vulnerability identified as CVE-2026-15667. The flaw resides in the handling of the 'event_layout' parameter within the plugin's REST API functionality. Authenticated users with the 'etn_manage_event' capability - which is assigned to the Contributor role by default - can exploit this parameter to point the application to arbitrary local files. If an attacker can upload a file with a .php extension to the server, this vulnerability allows them to include and execute that code, resulting in remote code execution (RCE). This issue is significant as it provides a pathway for lateral movement, privilege escalation, and sensitive data exfiltration by users who are already within the WordPress site's administrative hierarchy.

## Impact

Successful exploitation allows authenticated users with contributor-level permissions to execute arbitrary PHP code on the web server. This can lead to full site compromise, unauthorized database access, the modification of system configuration files, and the exfiltration of sensitive site data. Organizations relying on this plugin for event management are vulnerable if they allow untrusted users to hold contributor-level accounts.

## Recommendation

* Update the Eventin WordPress plugin to the latest version immediately to remediate the vulnerability associated with CVE-2026-15667.
* Audit WordPress user roles and capabilities to identify accounts with the 'etn_manage_event' capability and restrict these to trusted administrators only.
* Implement file integrity monitoring to detect the creation of unexpected or unauthorized .php files on the web server filesystem.
* Restrict file upload directories to prevent execution (e.g., set 'noexec' flags on uploads directories) as a defense-in-depth measure.
