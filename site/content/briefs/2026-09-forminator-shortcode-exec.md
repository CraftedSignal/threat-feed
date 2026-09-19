---
title: Arbitrary Shortcode Execution in Forminator WordPress Plugin
slug: 2026-09-forminator-shortcode-exec
description: The Forminator plugin for WordPress contains an arbitrary shortcode execution vulnerability (CVE-2026-92229) allowing unauthenticated attackers to execute arbitrary shortcodes by leveraging improper input validation.
date: "2026-09-19T04:08:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wpmu_dev:forminator:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - web-application
vendors:
  - WPMU DEV
products:
  - Forminator (<= 1.57.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to execute arbitrary shortcodes.
    confidence_band: high
cves:
  - id: CVE-2026-92229
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92229
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Forminator plugin to version 1.57.3 or higher.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92229 affects versions up to and including 1.57.2.
  mitigation_plan:
    - priority: immediate
      action: Identify and disable unnecessary shortcodes until patching is complete.
      owner: IT Operations
      addresses: CVE-2026-92229
      evidence: The vulnerability allows execution of arbitrary shortcodes due to lack of input validation.
---

The Forminator Forms - Contact Form, Payment Form & Custom Form Builder plugin for WordPress is affected by a critical vulnerability (CVE-2026-92229) impacting all versions up to and including 1.57.2. The vulnerability originates from a failure in the plugin to properly validate user-supplied input before passing it to the WordPress `do_shortcode()` function. By manipulating specific actions within the plugin, an unauthenticated attacker can force the application to execute arbitrary shortcodes. Because many WordPress plugins and themes register shortcodes that can perform sensitive operations, file modifications, or information disclosure, this flaw provides a vector for unauthorized system interaction. Depending on the environment and the shortcodes available in the installed plugin ecosystem, this can escalate to remote code execution (RCE) or full site compromise. Defenders should prioritize updating to the latest patched version and audit active shortcodes for potential exploitation.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary shortcodes within a WordPress environment. This can lead to unauthorized access to sensitive site data, unintended plugin configuration changes, or full system compromise if the target environment supports malicious or administrative shortcodes.

## Recommendation

Prioritize updating the Forminator plugin to the latest version beyond 1.57.2 as soon as the vendor provides a patch. Perform a site-wide audit of all installed plugins and themes to identify and disable unnecessary shortcodes that could be triggered by this vulnerability. Monitor web server access logs for anomalous HTTP requests containing shortcode-related parameters or patterns consistent with WordPress plugin exploitation.
