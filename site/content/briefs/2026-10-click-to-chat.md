---
title: CVE-2026-92097 - Arbitrary Shortcode Execution in Click to Chat for WhatsApp
slug: 2026-10-click-to-chat
description: An unauthenticated arbitrary shortcode execution vulnerability in Click to Chat for WhatsApp for WordPress allows attackers to trigger malicious shortcodes by manipulating the REQUEST_URI.
date: "2026-10-14T04:35:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:holithemes:click_to_chat_for_whatsapp:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - remote-code-execution
products:
  - Click to Chat for WhatsApp (<= 4.44)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to execute arbitrary shortcodes registered by WordPress core, the active theme, or any other plugin.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The attacker-controlled URL bytes reach do_shortcode() unfiltered.
    confidence_band: high
cves:
  - id: CVE-2026-92097
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92097
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update Click to Chat for WhatsApp to the patched version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-92097 severity warrants immediate remediation
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to filter URI requests containing suspicious shortcode characters '[' and ']' in query parameters
      owner: SOC
      addresses: CVE-2026-92097
      evidence: Exploit utilizes REQUEST_URI to inject shortcodes
---

The Click to Chat for WhatsApp plugin for WordPress versions 4.44 and earlier contains a vulnerability (CVE-2026-92097) that allows for unauthenticated arbitrary shortcode execution. The flaw exists within the greetings_dialog() function, which constructs the {url} template placeholder using the $_SERVER['REQUEST_URI'] variable. While this variable is filtered via sanitize_text_field(), the plugin fails to strip shortcode delimiters before passing the content to do_shortcode(). 

Crucially, the plugin applies wp_kses() to the content before performing the {url} substitution, meaning attacker-controlled malicious bytes are not neutralized by the security filter. By crafting a specific REQUEST_URI, an attacker can trigger any shortcode registered within the WordPress environment, including those defined by the theme or other installed plugins. This vulnerability can lead to unauthorized actions, data exfiltration, or potentially full remote code execution depending on the functionality of the available shortcodes within the target WordPress instance.

## Impact

The vulnerability carries a CVSS 3.1 base score of 9.1, indicating a high potential for compromise. If successfully exploited, an unauthenticated attacker could execute arbitrary code or perform administrative actions within the context of the WordPress site. The number of impacted installations is significant, given the popularity of WordPress plugins for customer engagement, potentially exposing numerous websites to site takeover or unauthorized backend operations.

## Recommendation

Prioritize the immediate update of the Click to Chat for WhatsApp plugin to a version addressing CVE-2026-92097. Detection engineering teams should monitor web server logs for suspicious characters in the URI that are associated with shortcode syntax, such as square brackets, that do not correspond to legitimate site navigation patterns.

- Update the Click to Chat for WhatsApp plugin to the latest available version containing the security patch for CVE-2026-92097.
- Implement Web Application Firewall (WAF) rules to inspect incoming URI requests for suspicious patterns, specifically looking for brackets '[' and ']' that may be used to initiate shortcode execution.
- Audit all active plugins for registered shortcodes that could be leveraged for elevated privileges or sensitive actions.
