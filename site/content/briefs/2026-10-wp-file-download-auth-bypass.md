---
title: Authorization Bypass in WP File Download Plugin
slug: 2026-10-wp-file-download-auth-bypass
description: An authorization bypass vulnerability in WP File Download allows authenticated users with subscriber-level access to delete or manipulate managed files.
date: "2026-10-10T07:52:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:joomunited:wp_file_download:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - web-application
vendors:
  - JoomUnited
products:
  - WP File Download (<= 6.3.9)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with subscriber-level access and above, to permanently delete any file managed by WP File Download.
    confidence_band: high
cves:
  - id: CVE-2026-94538
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94538
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade WP File Download to version 6.4.0 or later
      owner: IT Operations
      addresses: CVE-2026-94538
      evidence: Source identifies authorization bypass in versions up to 6.3.9
---

The WP File Download plugin for WordPress, in all versions up to and including 6.3.9, contains an authorization bypass vulnerability identified as CVE-2026-94538. The flaw stems from insufficient access control checks within the plugin, which fails to verify that the requesting user has the necessary privileges before executing sensitive management tasks. 

This vulnerability allows any authenticated user, including those with restricted 'subscriber' roles, to bypass intended authorization checks. Consequently, an attacker can perform administrative actions such as permanently deleting managed files, clearing the file trash, reorganizing file categories, and modifying the publication status of sensitive documents. This poses a significant risk to site integrity and data confidentiality, as unauthorized actors can disrupt file management operations or delete critical assets without administrative authorization. Organizations utilizing this plugin should prioritize updating to a patched version once released by JoomUnited.

## Impact

Successful exploitation allows unauthorized users to perform destructive actions against the plugin's file system, leading to data loss, service disruption, and the potential unauthorized exposure of restricted files if their publication status is manipulated.

## Recommendation

* Identify all WordPress instances running the WP File Download plugin.
* Update the WP File Download plugin to version 6.4.0 or the latest available patched version provided by JoomUnited.
* Restrict subscriber-level account creation and monitor user activity logs for suspicious administrative actions within the plugin's file management interface.
