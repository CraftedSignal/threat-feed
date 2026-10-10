---
title: CVE-2026-97670 Authorization Bypass in Avada Fusion Builder
slug: 2026-10-avada-builder-auth-bypass
description: An unauthenticated authorization bypass in the Avada Fusion Builder plugin for WordPress allows attackers to trigger arbitrary action hooks via crafted AJAX form submissions.
date: "2026-10-10T05:34:20Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:themefusion:avada:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - plugin-vulnerability
  - cve-2026-97670
vendors:
  - ThemeFusion
products:
  - Avada (Fusion) Builder (<= 7.16.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is due to the plugin not properly verifying authorization before dispatching a WordPress action hook whose name is taken from an attacker-supplied form-field value.
    confidence_band: high
cves:
  - id: CVE-2026-97670
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97670
rules:
  - title: Detect CVE-2026-97670 Exploitation - Suspicious Avada Form Hook Injection
    description: Detects unauthorized attempts to trigger WordPress hooks via Avada form submission by identifying the {action_hook sequence in HTTP POST requests.
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
    - action: Upgrade Avada Fusion Builder to a version exceeding 7.16.1
      owner: IT Operations
      due: 24h
      evidence: Plugin is vulnerable in all versions up to and including 7.16.1.
  mitigation_plan:
    - priority: immediate
      action: Update Avada Fusion Builder to patched version
      owner: IT Operations
      addresses: CVE-2026-97670
      evidence: Source confirms versions up to 7.16.1 are vulnerable.
---

The Avada Fusion Builder plugin for WordPress is vulnerable to an authorization bypass flaw (CVE-2026-97670) affecting all versions up to and including 7.16.1. The issue stems from the plugin's failure to verify authorization before dispatching WordPress action hooks parsed from attacker-supplied form data. Specifically, the plugin's dynamic-data token system handles the {action_hook,...} token within form notification email templates without adequate validation. Because the plugin's internal trust gate only inspects 'args' parameters and ignores 'formData' processed during AJAX submissions, an unauthenticated attacker can supply arbitrary hooks. When an Avada form with a notification template is submitted, the plugin executes these hooks, leading to unauthorized state changes. This can result in permanent site content deletion, denial of service, or the invocation of vulnerable third-party handlers. The vulnerability also facilitates a blind arbitrary meta-read, although exfiltration is limited by the plugin's response path.

## Attack Chain

1. Attacker identifies a WordPress site running a vulnerable version of Avada Fusion Builder.
2. Attacker locates a page containing a published Avada form with AJAX submission enabled.
3. Attacker crafts a POST request to the plugin's public form-submit endpoint containing malicious form data.
4. Attacker inserts a dynamic-data token, such as {action_hook,wp_scheduled_delete}, into the 'formData' parameters.
5. The plugin parses the 'formData', bypasses the incomplete 'is_content_request_supplied' security check, and fails to validate the hook name.
6. The plugin dispatches the requested WordPress action hook, executing the core function (e.g., permanent deletion of trashed posts).
7. Final objective: unauthorized site state modification, site content destruction, or service disruption.

## Impact

Successful exploitation allows unauthenticated attackers to trigger sensitive WordPress core and plugin-specific action hooks. This leads to the permanent, irreversible destruction of site content including posts, pages, and comments, as well as potential denial of service through auto-update hooks. While the vulnerability also allows for arbitrary meta-reading, observed exploitation vectors center on unauthorized administrative state changes and data loss.

## Recommendation

1. Immediately update the Avada Fusion Builder plugin to a version released after 7.16.1 to resolve CVE-2026-97670.
2. Monitor web server logs for suspicious POST requests to form submission endpoints that include patterns such as '{action_hook' or common WordPress administrative hooks.
3. Audit Avada form configurations to identify and sanitize active notification email templates that use dynamic-data tokens.
