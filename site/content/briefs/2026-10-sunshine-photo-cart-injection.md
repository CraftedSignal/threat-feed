---
title: PHP Object Injection in Sunshine Photo Cart WordPress Plugin
slug: 2026-10-sunshine-photo-cart-injection
description: The Sunshine Photo Cart plugin for WordPress is vulnerable to unauthenticated PHP object injection in versions up to 3.7.4, which can be leveraged for RCE if secondary plugins provide a viable POP chain.
date: "2026-10-16T08:24:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:sunshine_photo_cart_client_photo_gallery_photo_proofing_for_photographers:*:*:*:*:*:*:*:*
tags:
  - web-application
  - wordpress
  - injection
vendors:
  - WordPress
products:
  - Sunshine Photo Cart – Client Photo Gallery & Photo Proofing for Photographers (<= 3.7.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject a PHP Object.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: If a POP chain is present via an additional plugin or theme installed on the target system, it may allow the attacker to... execute code depending on the POP chain present.
    confidence_band: high
cves:
  - id: CVE-2026-104730
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104730
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update Sunshine Photo Cart to a version beyond 3.7.4
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-104730 vulnerability patch requirement
  mitigation_plan:
    - priority: immediate
      action: Block public access to non-essential plugin endpoints via WAF
      owner: SOC
      addresses: CVE-2026-104730
      evidence: Source states exploitation occurs via the public favorites page and image viewing endpoints
---

The Sunshine Photo Cart - Client Photo Gallery & Photo Proofing for Photographers plugin for WordPress is vulnerable to PHP Object Injection (CVE-2026-104730) in all versions up to and including 3.7.4. The vulnerability arises from the insecure deserialization of untrusted input. While the plugin itself does not contain a Property-Oriented Programming (POP) chain required for full exploitation, the vulnerability allows unauthenticated attackers to supply a malicious serialized object via the public favorites page. 

If the WordPress environment contains other plugins or themes that include a POP chain, this vulnerability can be successfully leveraged to achieve remote code execution, perform arbitrary file deletions, or retrieve sensitive data. Attackers can trigger the deserialization process by interacting with specific image viewing endpoints associated with non-viewable or private galleries. This vulnerability represents a significant risk for WordPress sites hosting multiple plugins where cross-plugin POP chain exploitation is possible.

## Impact

The impact of this vulnerability is contingent upon the existence of secondary POP chains within the target's WordPress installation. If such a chain exists, the vulnerability allows for unauthenticated remote code execution, unauthorized access to sensitive data, and potential system compromise. Given the prevalence of plugin-heavy WordPress environments, many installations are at risk of being exploited if a viable gadget chain is discovered in commonly deployed software.

## Recommendation

* Immediately update the Sunshine Photo Cart - Client Photo Gallery & Photo Proofing for Photographers plugin to the latest available version (beyond 3.7.4) to address the insecure deserialization logic.
* Audit installed WordPress plugins and themes for known POP chain gadgets, particularly those known to be utilized in object injection attacks.
* Deploy web application firewall (WAF) rules to block POST requests containing serialized PHP object strings (e.g., 'O:[0-9]+:"') directed at public-facing plugin endpoints until the site can be patched.
* Monitor web server logs for high volumes of 403 or 500 errors originating from unauthenticated users accessing private or non-viewable gallery images, which may indicate exploitation attempts.
