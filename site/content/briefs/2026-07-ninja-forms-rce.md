---
title: Ninja Forms Plugin Vulnerability Allows Network-Wide Data Deletion in WordPress Multisite
slug: 2026-07-ninja-forms-rce
description: A critical privilege escalation vulnerability, CVE-2026-65049, in the Ninja Forms plugin (version 3.14.8 and prior) for WordPress Multisite allows a subsite Administrator to trigger network-wide deletion of all Ninja Forms data by exploiting an incorrect authorization check combined with unsafe multisite migration defaults, leading to severe data loss.
date: "2026-07-21T15:20:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - data-deletion
  - webserver
  - cve
vendors:
  - Ninja Forms
  - WordPress
products:
  - Ninja Forms plugin (<= 3.14.8)
  - WordPress Multisite
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: a subsite Administrator to trigger network-wide deletion of all Ninja Forms data by exploiting a site-scoped capability check combined with unsafe multisite migration defaults.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allows a subsite Administrator to trigger network-wide deletion of all Ninja Forms data [...] without requiring super-admin or network-admin privileges.
    confidence_band: high
cves:
  - id: CVE-2026-65049
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65049
rules:
  - title: Detects CVE-2026-65049 Exploitation - Ninja Forms Network-Wide Data Deletion Attempt
    description: Detects CVE-2026-65049 exploitation - crafted HTTP POST request to /wp-admin/admin-ajax.php with action=nf_delete_all_data, indicating an attempt by a subsite administrator to trigger network-wide data deletion in Ninja Forms.
    platform: sigma
    severity: critical
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1068
      - T1485
    data_sources:
      - webserver
rules_count: 1
---

The Ninja Forms plugin, specifically versions 3.14.8 and prior, for WordPress Multisite contains a critical authorization vulnerability, identified as CVE-2026-65049. This flaw allows a subsite Administrator, who typically has limited privileges, to trigger a network-wide deletion of all Ninja Forms data across the entire WordPress Multisite instance. Attackers exploit an incorrect site-scoped capability check in conjunction with unsafe multisite migration defaults. By sending a specially crafted POST request to the `/wp-admin/admin-ajax.php` endpoint with the `nf_delete_all_data` action and a valid per-site nonce, the attacker can invoke migration routines. These routines then unconditionally iterate through all blogs via `switch_to_blog()`, dropping all `nf3_*` tables and clearing associated options and transients on every subsite, without requiring super-admin or network-admin privileges. This vulnerability poses a severe data loss risk and can lead to significant operational disruption for organizations using WordPress Multisite with the affected Ninja Forms plugin.

## Attack Chain

1. A subsite administrator, potentially a malicious insider or an external attacker who has gained subsite admin privileges, targets a vulnerable WordPress Multisite instance running Ninja Forms plugin version 3.14.8 or prior.
2. The attacker identifies the Ninja Forms plugin's AJAX action `nf_delete_all_data` as a potential vector for unauthorized operations.
3. A crafted HTTP POST request is prepared, targeting the `/wp-admin/admin-ajax.php` endpoint on the WordPress Multisite instance.
4. The request body includes the `action=nf_delete_all_data` parameter and a valid per-site nonce to authenticate the request as originating from a legitimate subsite administrator.
5. The WordPress application processes the request, and due to an incorrect authorization check, the `nf_delete_all_data` action is allowed to proceed despite the subsite administrator lacking network-wide privileges.
6. The Ninja Forms plugin's migration routines are invoked, which internally utilize `switch_to_blog()` to programmatically iterate through every subsite configured within the WordPress Multisite network.
7. During this iteration, for each subsite, the plugin executes commands to drop all `nf3_*` database tables and clears associated options and transients.
8. The final objective is achieved: all Ninja Forms data is completely deleted across the entire WordPress Multisite network, resulting in a denial of service and data loss.

## Impact

Successful exploitation of CVE-2026-65049 results in the complete deletion of all Ninja Forms data across every subsite within a WordPress Multisite installation. This leads to a severe denial of service, as all forms and associated submissions become permanently inaccessible. Organizations relying on Ninja Forms for critical business processes, data collection, or customer interactions will face significant operational disruption, data loss, and potential regulatory compliance issues. The impact extends beyond a single subsite, affecting the entire network, making recovery complex and time-consuming. The CVSS v3.1 base score for this vulnerability is 9.3 (Critical).

## Recommendation

* Immediately update the Ninja Forms plugin to a version greater than 3.14.8 on all WordPress Multisite installations to patch CVE-2026-65049.
* Deploy the provided Sigma rule to your SIEM to detect attempts to exploit the `admin-ajax.php` endpoint with the `nf_delete_all_data` action.
* Ensure web server logs (category `webserver`) are configured to capture full HTTP request details, including `cs-method`, `cs-uri-stem`, and `cs-uri-query`, to enable detection.
* Review access controls for all subsite administrators within WordPress Multisite environments, ensuring they operate with the principle of least privilege.
