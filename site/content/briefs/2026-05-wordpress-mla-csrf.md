---
title: Media Library Assistant WordPress Plugin vulnerable to CSRF (CVE-2026-6075)
slug: 2026-05-wordpress-mla-csrf
description: The Media Library Assistant plugin for WordPress is vulnerable to Cross-Site Request Forgery (CVE-2026-6075) due to missing nonce verification, allowing unauthenticated attackers to trick an administrator into performing unauthorized bulk actions.
date: "2026-05-29T09:18:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - csrf
  - plugin
vendors:
  - Wordfence
products:
  - Media Library Assistant plugin for WordPress <= 3.35
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-6075
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6075
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/0e399651-8992-4949-b7a7-4e8ce199b47a?source=cve
  - https://plugins.trac.wordpress.org/browser/media-library-assistant/tags/3.33/includes/class-mla-settings-custom-fields-tab.php#L664
  - https://plugins.trac.wordpress.org/browser/media-library-assistant/tags/3.33/includes/class-mla-settings-iptc-exif-tab.php#L804
  - https://plugins.trac.wordpress.org/browser/media-library-assistant/tags/3.33/includes/class-mla-settings-view-tab.php#L224
  - https://plugins.trac.wordpress.org/browser/media-library-assistant/tags/3.33/includes/class-mla-settings.php#L1331
  - https://plugins.trac.wordpress.org/browser/media-library-assistant/trunk/includes/class-mla-settings-custom-fields-tab.php#L664
  - https://plugins.trac.wordpress.org/browser/media-library-assistant/trunk/includes/class-mla-settings-iptc-exif-tab.php#L804
  - https://plugins.trac.wordpress.org/browser/media-library-assistant/trunk/includes/class-mla-settings-view-tab.php#L224
  - https://plugins.trac.wordpress.org/browser/media-library-assistant/trunk/includes/class-mla-settings.php#L1331
  - https://plugins.trac.wordpress.org/changeset/3494141/media-library-assistant/trunk/includes/class-mla-settings-custom-fields-tab.php
  - https://plugins.trac.wordpress.org/changeset?old_path=%2Fmedia-library-assistant/tags/3.34&new_path=%2Fmedia-library-assistant/tags/3.35
rules:
  - title: Detect WordPress Media Library Assistant CSRF Attempt
    description: Detects CVE-2026-6075 exploitation - Attempts to exploit the CSRF vulnerability in the Media Library Assistant plugin by monitoring for POST requests to specific plugin endpoints without a valid nonce.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect WordPress Plugin Settings Update without Nonce
    description: Detects attempts to update WordPress plugin settings without a valid nonce, potentially indicating a CSRF attack.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

The Media Library Assistant plugin for WordPress is susceptible to Cross-Site Request Forgery (CSRF) attacks in versions up to and including 3.35. The vulnerability stems from the absence of nonce verification in the bulk action handlers within the plugin's settings tab. An unauthenticated attacker can exploit this weakness by crafting a malicious request that, when triggered by a logged-in administrator, performs actions such as bulk deletion, editing, or purging of plugin settings and attachment metadata. This can lead to data loss, modification of plugin behavior, or other unintended consequences, highlighting the importance of timely patching.

## Attack Chain

1.  Attacker crafts a malicious HTML page containing a forged request targeting the vulnerable plugin's settings tab handlers.
2.  The attacker distributes the malicious HTML page to a WordPress administrator, often via social engineering techniques (e.g., phishing email or malicious link).
3.  The administrator, while logged into the WordPress admin panel, unknowingly visits the attacker-controlled HTML page.
4.  The malicious page automatically sends the forged request to the WordPress server, impersonating the administrator. This request targets a bulk action handler, such as those responsible for deleting attachment metadata.
5.  Due to the lack of nonce verification, the WordPress server processes the forged request as if it originated from the administrator.
6.  The targeted bulk action is executed, leading to the deletion, editing, or purging of plugin settings and attachment metadata, depending on the specific forged request.
7.  The attacker achieves the objective of manipulating the plugin settings or attachment metadata without direct authentication.

## Impact

Successful exploitation of this CSRF vulnerability can lead to unauthorized modification or deletion of Media Library Assistant plugin settings and associated attachment metadata. This could result in disruption of website functionality, data loss, or exposure of sensitive information. The scope of the impact depends on the specific actions the attacker is able to trigger via the forged request. Given the wide adoption of WordPress and its plugin ecosystem, a successful exploit could affect numerous websites.

## Recommendation

*   Upgrade the Media Library Assistant plugin to the latest version, which includes a fix for CVE-2026-6075.
*   Deploy the Sigma rule `Detect WordPress Media Library Assistant CSRF Attempt` to monitor for potential exploitation attempts targeting the vulnerable plugin.
*   Educate WordPress administrators about the risks of CSRF attacks and the importance of avoiding suspicious links or websites.
