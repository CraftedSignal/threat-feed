---
brief_id: brief-2026-11-03-azuracast-config-injection
event_id: brief-2026-11-03-azuracast-config-injection
revision: 1
activity_at: "2026-11-03T15:59:54Z"
title: 'AzuraCast: Configuration injection and privilege escalation (CVE-2026-121427)'
slug: 2026-11-azuracast-config-injection
description: AzuraCast versions 0.23.8 and earlier contain an authorization bypass vulnerability allowing users with limited permissions to inject arbitrary directives into the Shoutcast configuration file.
date: "2026-11-03T15:59:54Z"
lastmod: "2026-11-03T16:00:08Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified vulnerability details
cpes:
  - cpe:2.3:a:azuracast:azuracast:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-vulnerability
vendors:
  - AzuraCast
products:
  - AzuraCast (<= 0.23.8)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated user with only the Manage station profile permission can override adminpassword, password, and portbase.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: Attackers can inject shell metacharacters into stereo_tool_configuration_path or stereo_tool_license_key, which are executed via /bin/sh on station restart
    confidence_band: high
cves:
  - id: CVE-2026-121427
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-121429
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121427
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121429
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict "Profile" permissions for non-administrative users in AzuraCast to mitigate unauthorized configuration changes
      owner: IT Operations
      due: 24h
      evidence: Vulnerability requires Profile permissions for exploitation
  hunt_leads:
    - lead: Identify authenticated users modifying station profiles with potential malicious configuration payloads
      technique_id: T1068
      data_needed:
        - Web server access logs or application audit logs for PUT requests to /station/*/profile/edit
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Authenticated user with only the Manage station profile permission can override adminpassword, password, and portbase, or inject arbitrary directives via newlines in keys.
    - lead: Audit AzuraCast application logs for configuration changes involving the stereo_tool_configuration_path or stereo_tool_license_key fields
      technique_id: T1059
      data_needed:
        - AzuraCast application activity logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers manipulate stereo_tool_configuration_path or stereo_tool_license_key to trigger command injection
  mitigation_plan:
    - priority: immediate
      action: Audit user roles to ensure only trusted administrators hold Manage station profile permissions until patching is completed
      owner: IT Operations
      addresses: CVE-2026-121427
      evidence: An authenticated user with only the Manage station profile permission can override adminpassword, password, and portbase.
    - priority: immediate
      action: Upgrade AzuraCast to a version newer than 0.23.8
      owner: IT Operations
      addresses: CVE-2026-121429
      evidence: NVD advisory identifies versions through 0.23.8 as vulnerable
updates:
  - at: "2026-11-03T16:00:08Z"
    level: L2
    summary: added coverage for AzuraCast (<= 0.23.8)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121429
---

AzuraCast versions 0.23.8 and earlier are vulnerable to a configuration injection attack via the /station/{id}/profile/edit endpoint. The application fails to properly validate permissions or sanitize input for the frontend_config.custom_config field. Authenticated users with the Manage station profile permission can inject arbitrary directives into the Shoutcast sc_serv.conf file, enabling them to override critical security settings such as adminpassword and portbase.

## Impact
An attacker can hijack the Shoutcast frontend service by overriding authentication credentials and service configuration parameters, leading to a complete compromise of the station broadcasting service.

## Recommendation
- Upgrade AzuraCast to a version later than 0.23.8 once a patch is available.
- Review existing permissions for all users assigned the Manage station profile role to identify unauthorized configuration changes.
- Monitor logs for HTTP PUT requests to /station/*/profile/edit that include unusual JSON structures in the custom_config field.
