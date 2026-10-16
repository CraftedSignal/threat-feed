---
title: Stored XSS in RSS Aggregator by Feedzy WordPress Plugin
slug: 2026-10-feedzy-xss
description: The RSS Aggregator by Feedzy WordPress plugin is vulnerable to Stored Cross-Site Scripting via malicious RSS feed input, allowing unauthenticated attackers to execute arbitrary scripts in the context of the target site.
date: "2026-10-16T04:24:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:themeisle:rss_aggregator_by_feedzy:*:*:*:*:*:wordpress:*:*
tags:
  - web-application-vulnerability
  - wordpress
  - xss
vendors:
  - ThemeIsle
products:
  - RSS Aggregator by Feedzy – Feed to Post, Autoblogging, News & YouTube Video Feeds Aggregator (<= 5.2.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: An unauthenticated attacker controlling an external RSS feed can inject malicious scripts that execute in the context of the target WordPress site.
    confidence_band: high
cves:
  - id: CVE-2026-109207
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109207
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update RSS Aggregator by Feedzy plugin to the latest version on all WordPress instances.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109207 remediation requires updating the plugin.
  mitigation_plan:
    - priority: immediate
      action: Update RSS Aggregator by Feedzy to the latest patched version.
      owner: IT Operations
      addresses: CVE-2026-109207
      evidence: Plugin vulnerability found in versions <= 5.2.11.
---

The RSS Aggregator by Feedzy plugin for WordPress (versions 5.2.11 and below) contains a Stored Cross-Site Scripting (XSS) vulnerability. The flaw exists within the processing of the 'media:thumbnail@url' parameter of imported RSS feeds. Due to insufficient input sanitization and output escaping, an attacker who controls an external RSS feed can inject arbitrary JavaScript. When the target site imports this feed and a user views the resulting post or feed display, the injected script executes in the victim's browser. This attack is particularly effective as it requires no authentication on the target WordPress instance, relying instead on the existing configuration of the Feedzy plugin to pull content from an attacker-controlled external source. This vulnerability could lead to session hijacking, site defacement, or unauthorized actions performed on behalf of authenticated administrators or users.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of an administrator or visitor's session, potentially resulting in full administrative site compromise, session theft, or the redirection of users to malicious content. The vulnerability affects all WordPress sites utilizing Feedzy versions 5.2.11 or earlier, which is a widely used plugin for automated content aggregation.

## Recommendation

* Update the "RSS Aggregator by Feedzy" plugin to the latest version immediately to remediate the sanitization deficiency in the 'media:thumbnail@url' processing.
* Implement a strict Content Security Policy (CSP) to mitigate the impact of XSS by restricting the sources from which scripts can be loaded and preventing the execution of inline scripts.
* Review existing configured RSS sources within the plugin settings to identify and remove any feeds that are not explicitly trusted or maintained by the organization.
