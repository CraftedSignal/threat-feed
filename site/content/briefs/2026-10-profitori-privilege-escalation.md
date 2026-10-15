---
title: Unauthenticated Privilege Escalation in Profitori WordPress Plugin
slug: 2026-10-profitori-privilege-escalation
description: The Profitori plugin for WordPress, versions 2.0.6.0 through 2.1.1.3, contains a critical vulnerability (CVE-2025-4631) that allows unauthenticated remote attackers to escalate user privileges to Administrator via the REST API.
date: "2026-10-15T15:02:38Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:profitori:profitori:*:*:*:*:*:wordpress:*:*
products:
  - Profitori (2.0.6.0-2.1.1.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker can exploit the REST API endpoint /wp-json/stocktend/v1/stocktend_object by sending a request that modifies the wp_capabilities meta field.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated privilege escalation in Profitori plugin up to 2.1.1.3 via missing permission check.
    confidence_band: high
cves:
  - id: CVE-2025-4631
    cvss: 9.8
    epss: 0.00733
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-NXPLOITED-CVE-2025-4631
rules:
  - title: Detect CVE-2025-4631 Exploitation Attempt
    description: Detects unauthorized attempts to access the vulnerable stocktend_object REST API endpoint.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit WordPress assets for the presence of the Profitori plugin.
      owner: IT Operations
      due: 24h
      evidence: Source reporting of CVE-2025-4631 vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Disable or remove the Profitori plugin on all WordPress installations.
      owner: IT Operations
      addresses: CVE-2025-4631
      evidence: Plugin vulnerable up to version 2.1.1.3.
---

Profitori, a WordPress plugin, contains an unauthenticated privilege escalation vulnerability (CVE-2025-4631) affecting versions 2.0.6.0 through 2.1.1.3. The flaw resides in the `/wp-json/stocktend/v1/stocktend_object` REST API endpoint, which fails to perform proper authorization checks. Attackers can interact with this endpoint to directly manipulate the `wp_capabilities` meta field for any existing user ID on the site. By injecting the administrator capability into this field, an unauthorized actor can grant themselves or an existing account full administrative control. A public exploit script has been released, significantly increasing the risk of active exploitation. Organizations using the Profitori plugin are advised to verify their current version immediately.

## Attack Chain

1. Attacker performs reconnaissance to identify WordPress sites running the vulnerable Profitori plugin.
2. Attacker confirms the version by accessing the publicly available `/wp-content/plugins/profitori/readme.txt` file.
3. Attacker identifies a target user ID to compromise via public post author pages or administrative enumeration.
4. Attacker constructs a malicious POST request targeting the REST API endpoint `/wp-json/stocktend/v1/stocktend_object`.
5. The request body includes an updated `wp_capabilities` parameter set to grant administrative rights (e.g., `a:1:{s:13:"administrator";b:1;}`).
6. The vulnerable API endpoint processes the request without validating the attacker's session or permissions.
7. The target user's meta information is updated in the WordPress database, elevating their role to Administrator.
8. The attacker authenticates as the now-elevated user to gain full control over the WordPress instance.

## Impact

Successful exploitation grants an unauthenticated attacker full administrative access to the WordPress environment. This level of access typically results in complete system compromise, allowing the attacker to install arbitrary plugins, upload web shells, exfiltrate database contents, and perform further lateral movement within the hosting infrastructure.

## Recommendation

* Immediately audit all WordPress installations to identify if the Profitori plugin is active and running a version below 2.1.1.3.
* If identified, disable or remove the Profitori plugin until a vendor-supplied patch is installed.
* Monitor web server logs for suspicious POST requests targeting the `/wp-json/stocktend/v1/stocktend_object` path.
* Deploy the included detection rule to monitor for unauthorized API interactions with the plugin's endpoints.
