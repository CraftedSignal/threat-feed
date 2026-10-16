---
title: Sensitive Information Exposure in Modula Image Gallery Plugin
slug: 2026-10-modula-gallery-exposure
description: The Modula Image Gallery plugin for WordPress is vulnerable to unauthenticated information exposure via the REST API, allowing attackers to retrieve plaintext credentials for password-protected galleries.
date: "2026-10-16T06:25:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp-modula:modula:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - information-disclosure
  - rest-api
  - vulnerability
products:
  - Modula Image Gallery – Photo Grid & Video Gallery (<= 3.0.11)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: This makes it possible for unauthenticated attackers to extract the plaintext Password Protect password and username for every published gallery from the modulaSettings REST field.
    confidence_band: high
cves:
  - id: CVE-2026-107659
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107659
rules:
  - title: Detect CVE-2026-107659 - Unauthenticated Access to Modula Gallery REST API
    description: Detects unauthenticated GET requests to the vulnerable Modula Gallery REST API endpoint which may result in sensitive information exposure.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for exploitation attempts of CVE-2026-107659.
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms REST API is exploitable via unauthenticated GET requests.
  mitigation_plan:
    - priority: immediate
      action: Update Modula Image Gallery - Photo Grid & Video Gallery to the latest version immediately.
      owner: IT Operations
      addresses: CVE-2026-107659
      evidence: Plugin versions <= 3.0.11 are vulnerable.
---

The Modula Image Gallery - Photo Grid & Video Gallery plugin for WordPress (versions up to and including 3.0.11) contains a sensitive information exposure vulnerability identified as CVE-2026-107659. The issue exists due to inconsistent REST API security controls. While the plugin correctly redacts sensitive data in its own custom API endpoint (/wp-json/modula/v2/gallery/{id}/settings) via the redact_settings_for_public() function, it fails to implement the same protection for the core WordPress REST API endpoint (/wp-json/wp/v2/modula-gallery/{id}). 

Because the plugin registers its custom post type with 'show_in_rest' set to true, the core WordPress API exposes the plugin's metadata. Unauthenticated attackers can query this endpoint to retrieve the 'modulaSettings' field, which contains plaintext usernames and passwords used for password-protecting galleries. This exposure allows unauthorized access to private gallery content if those credentials are reused elsewhere. Defenders should monitor for unauthenticated requests targeting the vulnerable REST API endpoints.

## Impact

The vulnerability allows unauthenticated attackers to exfiltrate plaintext credentials (usernames and passwords) associated with password-protected galleries. This can lead to unauthorized access to gallery contents and potential credential stuffing attacks if users reuse these passwords on other systems. Given the prevalence of WordPress plugins in enterprise environments, the exposure of these credentials creates a significant risk of data breach and lateral movement.

## Recommendation

* Update the Modula Image Gallery - Photo Grid & Video Gallery plugin to the latest version immediately once a patch is released (version > 3.0.11).
* Monitor web server logs for unauthenticated GET requests targeting /wp-json/wp/v2/modula-gallery/ that return a 200 OK status.
* Audit existing WordPress installations to identify and remove stored credentials in gallery settings if they have been exposed.
* Block or restrict access to the WordPress REST API for untrusted IP ranges if the functionality is not required globally.
