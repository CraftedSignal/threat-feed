---
title: Arbitrary User Meta Write Vulnerability in Mapster WP Maps Plugin
slug: 2026-09-mapster-wp-maps-vuln
description: The Mapster WP Maps WordPress plugin contains an arbitrary user meta write vulnerability via the my_profile_update() function, allowing authenticated users with Subscriber-level access to overwrite arbitrary user metadata.
date: "2026-09-18T10:04:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mapster:wp_maps:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - wordpress
  - arbitrary-meta-write
vendors:
  - Mapster
products:
  - WP Maps (<= 1.23.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.002
    technique_name: 'Valid Accounts: Domain Accounts'
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to update arbitrary user meta values
    confidence_band: high
cves:
  - id: CVE-2026-12954
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12954
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review WordPress plugin inventory for Mapster WP Maps installation
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-12954
  mitigation_plan:
    - priority: immediate
      action: Update Mapster WP Maps plugin to version > 1.23.0 once available
      owner: IT Operations
      addresses: CVE-2026-12954
      evidence: NVD vulnerability details
  gaps:
    - Absence of vendor-provided patch version in the source report
---

The Mapster WP Maps plugin for WordPress, in versions up to and including 1.23.0, is susceptible to an arbitrary user meta write vulnerability. The flaw resides within the `my_profile_update()` function, which fails to implement necessary security controls, including nonce verification, capability checks, and allowlist validation for meta keys. 

An attacker with authenticated access (Subscriber-level or higher) can exploit this by submitting a crafted POST request containing the `acf-photo-gallery-groups` parameter. Because the plugin processes this input without validating the meta key or its associated value before executing the `update_user_meta()` function, an attacker can modify arbitrary user metadata fields. While the vulnerability does not directly facilitate privilege escalation, it can be leveraged to manipulate user profile data, potentially leading to unauthorized information modification or secondary impacts on account security depending on how other plugins or themes utilize user meta. Defenders should prioritize updating to the latest secure version once available.

## Impact

The vulnerability affects all users running Mapster WP Maps version 1.23.0 and earlier. Successful exploitation allows an authenticated attacker with minimal privileges (Subscriber) to modify arbitrary user metadata within the WordPress database. This can lead to account manipulation, potential data corruption, or the alteration of security-sensitive metadata used by other WordPress plugins, impacting the integrity of user accounts across the platform.

## Recommendation

* Monitor WordPress server logs for anomalous POST requests directed at the plugin endpoints associated with profile updates, specifically monitoring for the `acf-photo-gallery-groups` parameter in requests originating from low-privileged user accounts.
* Audit user metadata changes for unauthorized modifications occurring via the identified plugin function until an official patch is applied.
* Update the Mapster WP Maps plugin to the latest version as soon as a patch is released by the vendor to remediate the missing authorization and validation logic.
