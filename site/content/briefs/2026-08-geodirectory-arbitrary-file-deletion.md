---
title: Arbitrary File Deletion in GeoDirectory Plugin
slug: 2026-08-geodirectory-arbitrary-file-deletion
description: The GeoDirectory WordPress plugin contains an arbitrary file deletion vulnerability (CVE-2026-19091) allowing authenticated attackers to delete critical files and potentially achieve remote code execution.
date: "2026-08-11T21:51:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - wordpress
  - arbitrary-file-deletion
vendors:
  - AyeCode
products:
  - GeoDirectory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The GeoDirectory plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation.
    confidence_band: high
cves:
  - id: CVE-2026-19091
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19091
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch GeoDirectory plugin to version 2.8.170 or higher
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects versions up to 2.8.169
  hunt_leads:
    - lead: Identify subscriber-level users making POST requests to attachment or revision deletion endpoints
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploit requires authenticated access to manipulate attachment metadata
---

The GeoDirectory plugin for WordPress (all versions up to and including 2.8.169) is affected by a critical vulnerability, tracked as CVE-2026-19091, which permits arbitrary file deletion on the hosting server. The vulnerability resides within the `delete_revision` function, which fails to properly validate file paths during the deletion process. Authenticated attackers with subscriber-level access can manipulate the system by crafting specific queries to bypass consistency checks, effectively forcing the application to unlink files controlled via attachment metadata. 

This issue is significant because it allows an attacker to delete critical application files, such as 'wp-config.php'. By deleting this configuration file, an attacker can trigger a re-installation process or manipulate the application environment, potentially facilitating remote code execution or total site compromise. The exploit involves converting an auto-draft listing into an attachment to bypass validation mechanisms, demonstrating a breakdown in input sanitization and post-type verification within the plugin's core logic.

## Impact

Successful exploitation allows for the deletion of arbitrary files on the WordPress server, leading to potential service disruption, unauthorized installation redirection, and full remote code execution if sensitive configuration files are removed. This affects all websites utilizing the GeoDirectory plugin version 2.8.169 or earlier.

## Recommendation

* Immediately update the GeoDirectory plugin to the latest patched version available from the vendor.
* Audit access logs for subscriber-level users attempting to POST to the plugin's revision or attachment handling endpoints.
* Monitor for unauthorized file modification or deletion events targeting core WordPress files (e.g., wp-config.php).
* Enable web application firewall rules to detect and block suspicious requests containing post_type=attachment parameters in unauthorized contexts.
