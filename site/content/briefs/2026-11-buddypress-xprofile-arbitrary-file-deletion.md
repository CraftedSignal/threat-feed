---
brief_id: brief-2026-11-03-buddypress-xprofile-arbitrary-file-deletion
event_id: brief-2026-11-03-buddypress-xprofile-arbitrary-file-deletion
revision: 1
activity_at: "2026-11-03T05:54:24Z"
title: 'BuddyPress XProfile Image Field: Arbitrary file deletion (CVE-2026-120518)'
slug: 2026-11-buddypress-xprofile-arbitrary-file-deletion
description: The BuddyPress XProfile Image Field plugin for WordPress up to and including version 3.1.0 is vulnerable to arbitrary file deletion via unauthenticated registration metadata.
date: "2026-11-03T05:54:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - web-application
  - vulnerability
  - arbitrary-file-deletion
  - wordpress
products:
  - BuddyPress XProfile Image Field (<= 3.1.0)
cves:
  - id: CVE-2026-120518
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120518
---

The BuddyPress XProfile Image Field plugin for WordPress (up to and including 3.1.0) contains a vulnerability in the bpxp_image_field_update_on_user_activation() function. The plugin fails to validate visitor-supplied signup metadata, specifically when a zero-byte file is submitted with the 'field_N_hidden' parameter. This raw value is resolved against the document root upon activation, allowing unauthenticated attackers to delete arbitrary files on the server. Successful exploitation requires open registration and an image-type profile field on the signup form. Deletion of critical files, such as wp-config.php, can lead to remote code execution.
