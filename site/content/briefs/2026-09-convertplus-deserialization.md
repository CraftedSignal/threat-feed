---
title: 'CVE-2026-87741: Deserialization Vulnerability in WordPress ConvertPlus Plugin'
slug: 2026-09-convertplus-deserialization
description: An authenticated deserialization vulnerability in ConvertPlus <= 3.6.3 allows subscribers to inject arbitrary PHP objects via the cp_display_preview_modal AJAX action.
date: "2026-09-28T20:21:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:brainstormforce:convertplus:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - deserialization
  - web-vulnerability
vendors:
  - Brainstorm Force
products:
  - ConvertPlus (<= 3.6.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The ConvertPlus plugin for WordPress is vulnerable to Deserialization of Untrusted Data in all versions up to, and including, 3.6.3 via the style parameter of the cp_display_preview_modal AJAX action.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This makes it possible for authenticated attackers... to inject a PHP object... it may allow the attacker to perform actions like... execute code depending on the POP chain present.
    confidence_band: med
cves:
  - id: CVE-2026-87741
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87741
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade ConvertPlus to latest version.
      owner: IT Operations
      due: 48h
      evidence: Source states all versions up to 3.6.3 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version > 3.6.3
      owner: IT Operations
      addresses: CVE-2026-87741
      evidence: NVD vulnerability details
---

The ConvertPlus plugin for WordPress (versions 3.6.3 and earlier) is vulnerable to Deserialization of Untrusted Data. The vulnerability is triggered via the style parameter in the cp_display_preview_modal AJAX action. The flaw exists because the plugin fails to properly validate the cp_admin_page_nonce parameter; it defaults to a failed-open state when the parameter is omitted. Furthermore, the callback performs no capability checks and fails to strip shortcode delimiters from the style input. This allows a Subscriber-level user to inject a malicious [smile_modal] shortcode, which leads the smile_modal_popup function to pass attacker-supplied, base64-decoded data into the maybe_unserialize function without restricted class definitions. While ConvertPlus lacks its own POP chain, this vulnerability provides a critical vector for RCE or file manipulation if other installed themes or plugins contain exploitable POP chains.

## Impact

Successful exploitation requires a WordPress user account with at least Subscriber-level access. The impact is dependent on the presence of secondary POP chains within the target environment. If a compatible chain is present, attackers may achieve arbitrary file deletion, sensitive data retrieval, or remote code execution. Given the prevalence of WordPress plugin ecosystems, this increases the attack surface for sites using common plugin combinations.

## Recommendation

Prioritize updating the ConvertPlus plugin to the latest version. Monitor site-specific WordPress AJAX requests for signs of unauthorized access to the cp_display_preview_modal action.

- Update the ConvertPlus plugin to the latest available version beyond 3.6.3.
- Review installed plugins and themes to identify and remove software that contains known POP (Property Oriented Programming) chains.
- Audit logs for unexpected AJAX requests to /wp-admin/admin-ajax.php involving the cp_display_preview_modal action.
