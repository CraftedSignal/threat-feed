---
title: BuddyPress Insecure Deserialization Vulnerability
slug: 2026-07-buddypress-deserialization
description: An insecure deserialization vulnerability in the BuddyPress WordPress plugin allows authenticated attackers to inject arbitrary PHP objects, potentially leading to remote code execution.
date: "2026-07-30T07:19:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - deserialization
  - rce
  - web-vulnerability
vendors:
  - WordPress
products:
  - BuddyPress (<= 14.5.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for authenticated attackers... to inject arbitrary PHP objects... which could lead to remote code execution.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1360
---

The BuddyPress plugin for WordPress is vulnerable to an insecure deserialization flaw affecting all versions up to and including 14.5.0. The vulnerability resides in the `bp_unserialize_profile_field()` function, which invokes the native PHP `@unserialize()` function on XProfile textbox field data without specifying the `allowed_classes` parameter. Because the function processes user-controlled input, authenticated attackers with subscriber-level permissions or higher can inject malicious serialized PHP objects. If the target WordPress environment contains a suitable Property-Oriented Programming (POP) chain within its core, theme, or other installed plugins, this vulnerability can be leveraged to achieve remote code execution (RCE). The impact is significant due to the broad use of BuddyPress, and defenders should prioritize patching or restricting access to profile modification endpoints.

## Attack Chain

1. Attacker authenticates to the target WordPress site as a subscriber or user with profile modification permissions.
2. Attacker navigates to the XProfile field management or user profile settings interface.
3. Attacker crafts a malicious serialized PHP object designed to trigger a POP chain within the WordPress application environment.
4. Attacker submits the crafted payload via a textbox field POST request targeting the BuddyPress profile update endpoint.
5. The `bp_unserialize_profile_field()` function receives the malicious payload.
6. The application performs insecure deserialization of the injected object using `@unserialize()`.
7. The instantiated object triggers the POP chain during its lifecycle, resulting in unauthorized code execution.

## Impact

The vulnerability poses a high risk to WordPress installations utilizing the BuddyPress plugin. Successful exploitation by an authenticated attacker can result in full site compromise, arbitrary command execution on the underlying server, and potential data exfiltration or site defacement. Given that the attack requires only basic subscriber access, the pool of potential attackers is large in multi-user environments.

## Recommendation

* Update the BuddyPress plugin to a version later than 14.5.0 immediately to mitigate CVE-2026-1360.
* Audit WordPress environments for POP chain gadgets, particularly within custom plugins and themes, to understand the potential for secondary exploitation.
* Monitor web server logs for suspicious POST requests to BuddyPress profile update endpoints that contain PHP serialized data patterns (e.g., `O:[0-9]+:`) in the input parameters.
