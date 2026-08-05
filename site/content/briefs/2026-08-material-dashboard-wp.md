---
title: Unauthenticated Authorization Bypass in Material Dashboard WordPress Plugin
slug: 2026-08-material-dashboard-wp
description: The Material Dashboard plugin for WordPress contains a missing authorization vulnerability (CVE-2026-6079) allowing unauthenticated attackers to enumerate, execute, or delete scheduled tasks.
date: "2026-08-05T09:16:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - vulnerability
  - cve
vendors:
  - ho3einie
products:
  - Material Dashboard (1.4.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to enumerate all scheduled tasks... via the public_amd_ajax_handler AJAX action.
    confidence_band: high
cves:
  - id: CVE-2026-6079
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6079
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/459b7fef-806c-4f5b-bb31-b7197750e941?source=cve
rules:
  - title: Detects CVE-2026-6079 Exploitation - Unauthorized AJAX Task Handler
    description: Detects exploitation attempts against the Material Dashboard plugin by monitoring for the public_amd_ajax_handler action in AJAX requests.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update Material Dashboard plugin to 1.4.11+
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-6079 patch guidance
  hunt_leads:
    - lead: Search logs for public_amd_ajax_handler action from unauthorized IPs
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies this specific AJAX handler as the vulnerability vector
  mitigation_plan:
    - priority: immediate
      action: Monitor or block requests to admin-ajax.php containing the vulnerable action
      owner: SOC
      addresses: CVE-2026-6079
      evidence: Vulnerability analysis indicates public access to AJAX handler
---

The Material Dashboard plugin for WordPress (all versions up to and including 1.4.10) is vulnerable to unauthorized access and modification of data due to missing capability checks on the amd_ajax_target_task_manager() function. This flaw allows unauthenticated remote attackers to interact with the plugin's task management interface via the public_amd_ajax_handler AJAX action. Successful exploitation enables an attacker to enumerate all scheduled tasks, potentially exposing sensitive information or PII, execute arbitrary tasks, or delete tasks within the WordPress environment. This vulnerability stems from a lack of proper authorization validation before performing administrative actions, effectively granting unauthenticated users the ability to manipulate internal task scheduling.

## Attack Chain

1. Attacker performs reconnaissance on the target WordPress site to confirm the presence of the Material Dashboard plugin.
2. Attacker crafts an HTTP POST request targeting the WordPress admin-ajax.php endpoint.
3. Attacker specifies the 'public_amd_ajax_handler' action within the request parameters.
4. Attacker includes specific parameters to target the vulnerable amd_ajax_target_task_manager() function.
5. The plugin fails to verify the user's authorization/capabilities due to the missing check.
6. The plugin processes the request, allowing the attacker to list, trigger, or delete scheduled tasks.
7. Attacker achieves the final objective of unauthorized data modification or information disclosure via the manipulated tasks.

## Impact

Successful exploitation of this vulnerability leads to unauthorized administrative control over plugin tasks. This includes potential information disclosure of PII contained in scheduled tasks, disruption of site functionality by deleting tasks, and unauthorized execution of tasks, which could be leveraged to further compromise the WordPress instance depending on the specific tasks configured.

## Recommendation

Prioritize patching the Material Dashboard plugin immediately to version 1.4.11 or higher where authorization checks have been implemented. Use the web server logs to identify requests containing the 'public_amd_ajax_handler' action parameter to determine if this endpoint has been probed by unauthorized sources. If patching is not immediately feasible, restrict access to the WordPress admin-ajax.php endpoint at the web application firewall (WAF) layer or disable the plugin to mitigate the risk of unauthorized task manipulation.
