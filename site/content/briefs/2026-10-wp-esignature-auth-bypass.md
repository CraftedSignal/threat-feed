---
title: Authorization Bypass in Electronic Signature Add-on for Fluent Forms
slug: 2026-10-wp-esignature-auth-bypass
description: CVE-2026-110383 is an authorization bypass vulnerability in the Electronic Signature Add-on for Fluent Forms that permits attackers to manipulate access control levels due to improper user-controlled key handling.
date: "2026-10-18T11:57:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp_e-signature:electronic_signature_add-on_for_fluent_forms:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - authorization-bypass
  - wordpress
  - cve
vendors:
  - WP E-Signature
products:
  - Electronic Signature Add-on for Fluent Forms (<= 2.0.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify System Firewall'
    evidence: Authorization Bypass Through User-Controlled Key vulnerability... allows Exploiting Incorrectly Configured Access Control Security Levels.
    confidence_band: high
cves:
  - id: CVE-2026-110383
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110383
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Electronic Signature Add-on for Fluent Forms to version 2.0.6 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-110383 affects versions up to 2.0.5
  mitigation_plan:
    - priority: immediate
      action: Restrict admin access to WordPress dashboard
      owner: IT Operations
      addresses: CVE-2026-110383
      evidence: Mitigates potential for unauthorized exploitation
---

The Electronic Signature Add-on for Fluent Forms (WP E-Signature) contains an authorization bypass vulnerability identified as CVE-2026-110383. The flaw exists in versions 2.0.5 and below. It arises from the improper validation or handling of user-controlled keys, which allows an unauthenticated or low-privileged actor to manipulate access control security levels. By exploiting this mechanism, an attacker can bypass intended permission checks, potentially gaining unauthorized administrative access or modifying signature workflows within the plugin context. Given the nature of the application, this could lead to the exposure of sensitive documents or the modification of legal agreements managed by the plugin. Defenders should prioritize updating to the latest secure version of the plugin as soon as it is available from the vendor.

## Impact

Successful exploitation allows unauthorized access to administrative functions and potential modification of legal signature processes. This poses a significant risk to the integrity of contracts and documents stored or managed via the Electronic Signature Add-on for Fluent Forms. The vulnerability is rated with a CVSS v3.1 base score of 7.5, indicating a high risk to availability and confidentiality of the targeted WordPress environment.

## Recommendation

* Update the Electronic Signature Add-on for Fluent Forms to a version patched against CVE-2026-110383 (version 2.0.6 or later).
* Review administrative access logs for the WordPress site to identify unauthorized modifications to plugin configuration settings.
* Restrict administrative access to the WordPress dashboard to known, secure IP ranges to mitigate the impact of authorization bypass attempts.
