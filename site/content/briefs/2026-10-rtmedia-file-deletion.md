---
title: Unauthenticated Arbitrary File Deletion in rtMedia Plugin for WordPress
slug: 2026-10-rtmedia-file-deletion
description: The rtMedia for WordPress plugin contains a vulnerability in the 'process' function allowing unauthenticated attackers to delete arbitrary files on the server by leveraging exposed nonces.
date: "2026-10-10T05:34:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rtcamp:rtmedia_for_wordpress_buddypress_and_bbpress:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - vulnerability
  - web-application
  - file-deletion
vendors:
  - rtCamp
products:
  - rtMedia for WordPress, BuddyPress and bbPress (<= 4.7.13)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The rtMedia for WordPress, BuddyPress and bbPress plugin for WordPress is vulnerable to limited file deletion due to insufficient file path validation in the process function.
    confidence_band: high
cves:
  - id: CVE-2026-89301
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89301
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update rtMedia for WordPress, BuddyPress and bbPress to a patched version beyond 4.7.13.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-89301 patch required.
  mitigation_plan:
    - priority: immediate
      action: Patch plugin to version > 4.7.13
      owner: IT Operations
      addresses: CVE-2026-89301
      evidence: Source advisory
---

The rtMedia for WordPress, BuddyPress, and bbPress plugin, developed by rtCamp, contains a critical vulnerability (CVE-2026-89301) affecting all versions up to and including 4.7.13. The vulnerability stems from insufficient file path validation within the plugin's 'process' function. An unauthenticated attacker can exploit this to perform arbitrary file deletion on the hosting server. 

The attack vector is enabled by the exposure of the 'rtmedia_upload_nonce' security token within frontend JavaScript. This token is rendered on any page utilizing the rtMedia gallery or upload shortcode. Because the plugin does not require prior authentication to retrieve this nonce, an attacker can harvest it from the public-facing HTML/JS and subsequently use it to invoke the vulnerable file processing routine. This poses a significant risk to site integrity, potentially allowing for the removal of critical configuration or site files.

## Impact

Successful exploitation allows unauthenticated remote attackers to delete arbitrary files on the affected WordPress installation. This can result in complete site downtime, loss of functionality, or the removal of core security configurations, leading to a total loss of availability and integrity for the web application.

## Recommendation

Prioritized actions for security and infrastructure teams:

- Update the rtMedia for WordPress, BuddyPress and bbPress plugin to a version released after 4.7.13 immediately to patch the 'process' function path validation.
- Review web server access logs for anomalous POST requests directed at rtMedia processing endpoints that correspond with file deletion patterns.
- Implement Web Application Firewall (WAF) rules to restrict access to the rtMedia upload and processing paths if an immediate plugin update is not feasible.
