---
title: Unauthenticated Information Disclosure in Modula Image Gallery
slug: 2026-09-modula-gallery-leak
description: An unauthenticated access control vulnerability in the Modula Image Gallery WordPress plugin (<= 3.0.1) allows attackers to enumerate private gallery contents and download images via insecure meta tag generation.
date: "2026-09-25T08:57:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:modula:image_gallery_photo_grid_video_gallery:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - information-disclosure
  - cve-2026-89406
vendors:
  - Modula
products:
  - Modula Image Gallery – Photo Grid & Video Gallery (<= 3.0.1)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: This makes it possible for unauthenticated attackers to enumerate private modula-gallery posts and their member attachments.
    confidence_band: high
cves:
  - id: CVE-2026-89406
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89406
rules:
  - title: Detect CVE-2026-89406 Exploitation - Unauthorized Gallery Metadata Access
    description: Detects unauthorized attempts to access Modula gallery metadata via the modula_gallery_id parameter.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Modula Image Gallery plugin
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-89406 vulnerability advisory
  hunt_leads:
    - lead: Search logs for high-frequency hits on modula_gallery_id across different numeric values
      technique_id: T1082
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source notes enumeration potential
  mitigation_plan:
    - priority: immediate
      action: Block or limit access to the modula_gallery_id URL parameter
      owner: IT Operations
      addresses: CVE-2026-89406
      evidence: Vulnerability allows unauthenticated access via parameter
---

The Modula Image Gallery - Photo Grid & Video Gallery plugin for WordPress is affected by an unauthenticated information disclosure vulnerability tracked as CVE-2026-89406. The issue resides in the Modula_Meta::add_metas() function, which executes on every frontend request. Due to a logical error in the parameter validation - specifically, testing a hardcoded string instead of the provided input - the plugin fails to enforce access controls when a 'modula_gallery_id' GET parameter is supplied.

The plugin verifies that the requested post is of the type 'modula-gallery' but neglects to check the post_status or the user's authorization level. Consequently, the plugin emits Open Graph and Twitter meta tags containing sensitive gallery metadata (titles, descriptions, dimensions, and original file URLs) into the HTML response. An attacker can leverage these leaked URLs to download full-resolution private image files without authentication. This vulnerability impacts all versions up to and including 3.0.1.

## Attack Chain

1. Attacker identifies a WordPress site running the Modula Image Gallery plugin.
2. Attacker crafts a GET request targeting the site, appending the 'modula_gallery_id' parameter with a guessed or enumerated gallery ID.
3. The vulnerable Modula_Meta::add_metas() function hook fires during the WordPress frontend page load.
4. The plugin performs a database lookup for the provided ID via get_post() without verifying the requester's identity or post status.
5. The plugin fails the 'empty' input guard check due to the logic error, proceeding to process the requested gallery object.
6. The server generates an HTML response containing Open Graph and Twitter meta tags that expose the private image metadata and direct source URL.
7. Attacker parses the HTML response to extract the original high-resolution image URL.
8. Attacker requests the extracted image URL to perform unauthorized exfiltration of the private image file.

## Impact

Successful exploitation allows unauthorized third parties to download private, restricted, or draft images hosted within the gallery. This impacts photographers and site owners who rely on WordPress privacy settings to protect sensitive or non-public visual content. In environments with large galleries, the metadata enumeration can be automated to scrape entire private collections.

## Recommendation

Update the Modula Image Gallery - Photo Grid & Video Gallery plugin to the latest version, ensuring the patch for CVE-2026-89406 is applied. Until an update is installed, implement web server-level filtering to block requests containing the 'modula_gallery_id' parameter from untrusted sources.

- Update Modula Image Gallery to the version that remediates CVE-2026-89406.
- Monitor web server access logs for anomalous requests containing 'modula_gallery_id'.
- Deploy Web Application Firewall rules to block direct access to 'modula_gallery_id' parameters if immediate patching is not possible.
