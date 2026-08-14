---
title: Stored Cross-Site Scripting in W3 Total Cache
slug: 2026-08-w3-total-cache-xss
description: The W3 Total Cache plugin for WordPress versions up to 2.10.3 is vulnerable to Stored Cross-Site Scripting when the Lazy Load Images feature is enabled, allowing unauthenticated attackers to inject malicious scripts via comment author names.
date: "2026-08-14T04:06:10Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - BoldGrid
products:
  - W3 Total Cache
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: The LazyLoad mutator's img tag rewriting step... makes it possible for unauthenticated attackers to inject arbitrary web scripts
    confidence_band: high
cves:
  - id: CVE-2026-18109
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18109
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update W3 Total Cache to version 2.10.4 or higher
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18109 patch availability
  mitigation_plan:
    - priority: immediate
      action: Disable Lazy Load Images feature
      owner: IT Operations
      addresses: CVE-2026-18109
      evidence: This vulnerability is only exploitable when the Lazy Load Images feature of W3 Total Cache is enabled
---

The W3 Total Cache plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) due to insufficient input sanitization and output escaping when processing comment author names. This vulnerability, identified as CVE-2026-18109, affects all versions up to and including 2.10.3. The flaw is specifically triggered when the 'Lazy Load Images' feature is enabled. The vulnerability exists because the plugin's LazyLoad mutator performs unsafe re-emission of data during the img tag rewriting process. An unauthenticated attacker can supply a crafted string as an author name in a comment, which is then stored by the application and injected into pages where images are lazy-loaded. When an unsuspecting user, such as an administrator, views a page containing the injected comment, the malicious script executes within their browser context, potentially leading to session hijacking, unauthorized actions, or site redirection.

## Attack Chain

1. Attacker identifies a target WordPress site using W3 Total Cache with the 'Lazy Load Images' feature enabled.
2. Attacker submits a new comment on a public post, populating the 'Author Name' field with a payload containing malicious JavaScript (e.g., &lt;script>alert(1)&lt;/script>).
3. The WordPress application accepts the comment and stores the malicious payload in the 'comment_author' database column.
4. The W3 Total Cache plugin detects the comment during page rendering.
5. The plugin's LazyLoad mutator attempts to process images on the page and incorrectly re-emits the stored 'comment_author' string within an HTML attribute or tag content.
6. The injected script is rendered into the HTML of the page served to visitors.
7. A legitimate user (e.g., an administrator) navigates to the compromised page.
8. The victim's browser executes the attacker-supplied script, resulting in potential account takeover or unauthorized operations.

## Impact

The vulnerability allows unauthenticated remote attackers to execute arbitrary web scripts in the browser of any user who views the affected content. This poses a significant risk for administrative account compromise, as administrators frequently view comment moderation queues or pages where comments appear. If successful, this can lead to full site takeover, configuration changes, or the installation of malicious plugins.

## Recommendation

* Update the W3 Total Cache plugin to a version beyond 2.10.3 immediately to patch CVE-2026-18109.
* Disable the 'Lazy Load Images' feature in W3 Total Cache until the update can be applied to mitigate the specific attack vector.
* Audit existing comments on WordPress sites for anomalous characters or script tags in the author name field.
* Enable Content Security Policy (CSP) headers to restrict the execution of inline scripts and unauthorized external resources.
