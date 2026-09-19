---
title: Arbitrary Shortcode Execution in WP Recipe Maker Plugin
slug: 2026-09-wp-recipe-maker-rce
description: The WP Recipe Maker plugin for WordPress (<= 10.8.1) is vulnerable to arbitrary shortcode execution due to recursive do_shortcode calls on user-supplied metadata fields.
date: "2026-09-19T04:08:39Z"
lastmod: "2026-09-19T21:59:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp_recipe_maker:wp_recipe_maker:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=D6E93E8E-94F1-5A30-A541-24A9B186A2C1&utm_source=rss&utm_medium=rss
tags:
  - web-vulnerability
  - wordpress
  - cve-2026-89274
vendors:
  - WordPress
products:
  - WP Recipe Maker (<= 10.8.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to execute arbitrary registered WordPress shortcodes server-side on every recipe page render.
    confidence_band: high
cves:
  - id: CVE-2026-89274
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89274
  - https://sploitus.com/exploit?id=D6E93E8E-94F1-5A30-A541-24A9B186A2C1&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade WP Recipe Maker to the latest patched version
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability exists in versions <= 10.8.1
  mitigation_plan:
    - priority: immediate
      action: Enable strict comment moderation
      owner: Site Administrators
      addresses: CVE-2026-89274
      evidence: Exploitation requires comment approval
updates:
  - at: "2026-09-19T21:59:29Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=D6E93E8E-94F1-5A30-A541-24A9B186A2C1&utm_source=rss&utm_medium=rss
---

The WP Recipe Maker plugin for WordPress contains a critical vulnerability (CVE-2026-89274) in its metadata sanitization logic. The function `WPRM_Metadata::sanitize_metadata()` recursively processes recipe structured metadata arrays by invoking `do_shortcode()` on scalar fields. Specifically, the `reviewBody` field is populated using the raw `comment_content` of user-submitted `wprm-comment-rating` comments. Because the plugin performs tag and shortcode stripping only after the `do_shortcode()` call has been executed, it fails to sanitize malicious shortcode tokens. This flaw permits unauthenticated attackers to trigger server-side execution of registered WordPress shortcodes when a recipe page is rendered. Successful exploitation allows for the disclosure of sensitive information, such as private post data or attachment details, which are then rendered into the page's JSON-LD metadata for all visitors to see. The exploit requires the malicious comment to be approved, either through site settings or human intervention.

## Attack Chain

1. Attacker crafts a malicious comment containing a target WordPress shortcode.
2. Attacker submits the comment through the `wprm-comment-rating` input on a recipe page.
3. The WordPress site administrator or automated process approves the comment.
4. The WP Recipe Maker plugin processes the recipe metadata for display.
5. `WPRM_Metadata::sanitize_metadata()` pulls the raw `comment_content` into the `reviewBody` field.
6. The plugin calls `do_shortcode()` on the `reviewBody` string, executing the injected shortcode server-side.
7. The sensitive data rendered by the shortcode is stored in the JSON-LD structure of the recipe page.
8. Any visitor loading the recipe page receives the sensitive information within the page's JSON-LD output.

## Impact

The vulnerability poses a significant risk of information disclosure across WordPress installations using the WP Recipe Maker plugin. Attackers can leverage this to exfiltrate private post content, system information, or other data exposed via shortcodes. By embedding this information in publicly accessible JSON-LD metadata, the attacker ensures the leaked data is visible to any browser loading the affected recipe page.

## Recommendation

1. Upgrade the WP Recipe Maker plugin to a version beyond 10.8.1 immediately to resolve CVE-2026-89274.
2. Implement strict moderation policies for comments on recipe pages to prevent unapproved content from being rendered by the plugin.
3. Conduct an audit of all active shortcodes on the WordPress instance to identify those that could expose sensitive data if triggered via this vulnerability.
