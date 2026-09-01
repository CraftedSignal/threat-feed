---
title: Stored XSS Vulnerability in Listdom WordPress Plugin
slug: 2026-09-listdom-xss
description: An unauthenticated stored XSS vulnerability in the Listdom WordPress plugin allows attackers to inject arbitrary scripts when specific premium add-ons are enabled.
date: "2026-09-01T07:03:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:listdom:listdom:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - wordpress
  - web-vulnerability
vendors:
  - WordPress
products:
  - 'Listdom: AI-powered Business Directory with Classifieds Ads Listings (<= 5.8.1)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-19796
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19796
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update Listdom plugin to a version higher than 5.8.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-19796 remediation
  mitigation_plan:
    - priority: immediate
      action: Disable Listdom Pro add-on or 'Display Options Per Listing' setting if patching is delayed
      owner: IT Operations
      addresses: CVE-2026-19796
      evidence: Source identifies these as non-default requirements for exploitation
---

The Listdom: AI-powered Business Directory with Classifieds Ads Listings plugin for WordPress contains a stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-19796. The vulnerability stems from insufficient sanitization and escaping of user-supplied input within the 'lsd[displ][style]' parameter.

The issue affects all plugin versions up to and including 5.8.1. Successful exploitation allows an unauthenticated attacker to inject malicious JavaScript into web pages rendered by the plugin. This script executes within the context of the browser session of any user who accesses the compromised page, potentially leading to session hijacking, unauthorized actions, or further client-side exploitation. This vulnerability requires non-default configurations to be present, specifically the activation of the Listdom Pro add-on and the enabling of the 'Display Options Per Listing' setting.

## Impact

Successful exploitation results in the execution of arbitrary JavaScript in the victim's browser session. This can lead to account takeover, unauthorized modification of content, or data theft. The vulnerability affects websites utilizing the Listdom plugin with specific premium add-ons enabled, creating a significant risk for directories and classified sites running these components.

## Recommendation

1. Update the Listdom: AI-powered Business Directory with Classifieds Ads Listings plugin to the latest version beyond 5.8.1 to incorporate input sanitization patches for CVE-2026-19796.
2. If an immediate update is not possible, disable the Listdom Pro add-on or the 'Display Options Per Listing' functionality to mitigate the exploit path.
3. Deploy web application firewall (WAF) rules to detect and block malicious script injection attempts in POST requests targeting the plugin's configuration parameters.
