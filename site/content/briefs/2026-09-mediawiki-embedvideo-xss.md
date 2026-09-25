---
title: Stored XSS in MediaWiki EmbedVideo Extension via Unsanitized iframe Parameters
slug: 2026-09-mediawiki-embedvideo-xss
description: The EmbedVideo MediaWiki extension contains a stored Cross-Site Scripting (XSS) vulnerability that allows attackers to inject malicious JavaScript into wiki pages when the configuration $wgEmbedVideoRequireConsent is disabled.
date: "2026-09-25T20:06:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mediawiki:embedvideo:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - mediawiki
  - vulnerability
vendors:
  - MediaWiki
products:
  - EmbedVideo (<= 4.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any user able to edit a page can inject arbitrary JavaScript into an HTML event handler attribute
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: executes in the wiki origin for every visitor to the page
    confidence_band: high
cves:
  - id: CVE-2026-57440
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-v65j-hff3-753c
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-57440
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade EmbedVideo to 4.1.0 or later
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends update to patch CVE-2026-57440
  mitigation_plan:
    - priority: immediate
      action: Enable $wgEmbedVideoRequireConsent in MediaWiki configuration
      owner: IT Operations
      addresses: CVE-2026-57440
      evidence: Vulnerability manifests when $wgEmbedVideoRequireConsent = false
---

The EmbedVideo extension for MediaWiki (version 4.0.0 and earlier) contains a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-57440). The flaw exists when the non-default configuration $wgEmbedVideoRequireConsent is disabled. Under this configuration, the extension fails to sanitize video service URLs or IDs before passing them into the src attribute of an iframe. Because the regex patterns for specific services like archiveorg, wistia, and sharepoint allow double quotes, an attacker with page-editing permissions can escape the attribute context and inject arbitrary HTML event handler attributes, such as onfocus or onmouseover. This allows for the execution of unauthorized JavaScript in the context of the wiki origin when a victim views the affected page, leading to potential session hijacking or further malicious activity.

## Impact

Successful exploitation allows any user with page-editing capabilities to achieve stored XSS. The injected payload executes automatically in the browser of any visitor viewing the compromised page, operating within the victim's session context on the wiki domain. This significantly increases the risk of account takeovers and unauthorized actions being performed on behalf of legitimate users, impacting the integrity of the wiki platform and its stored content.

## Recommendation

Prioritize the following actions to secure the MediaWiki environment:

- Upgrade the EmbedVideo extension to a version beyond 4.0.0 immediately.
- Review the configuration file for the MediaWiki installation to ensure $wgEmbedVideoRequireConsent is set to true unless strictly required, as the vulnerability is dependent on this setting being disabled.
- Audit existing wiki pages for the presence of the &lt;embedvideo> tag, particularly those added or modified by untrusted contributors, to check for signs of injection containing event handlers like onmouseover or onfocus.
