---
brief_id: brief-2026-10-28-contact-manager-wordpress-rce
event_id: brief-2026-10-28-contact-manager-wordpress-rce
revision: 1
activity_at: "2026-10-28T08:26:09Z"
title: 'WordPress Contact Manager: Arbitrary File Upload (CVE-2026-109218)'
slug: 2026-10-contact-manager-wordpress-rce
description: The Contact Manager plugin for WordPress contains an arbitrary file upload vulnerability (CVE-2026-109218) in the add_message function, potentially allowing remote code execution for unauthenticated attackers.
date: "2026-10-28T08:26:09Z"
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
cpes:
  - cpe:2.3:a:wordpress:contact_manager:*:*:*:*:*:*:*:*
vendors:
  - WordPress
products:
  - Contact Manager (<= 9.1.2)
cves:
  - id: CVE-2026-109218
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109218
---

The Contact Manager plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to and including 9.1.2 via the add_message function. The vulnerability arises from an incomplete extension blacklist; a trailing dot causes the extension-derivation routine to return an empty string, which sanitize_file_name() then silently removes. This may allow unauthenticated attackers to upload executable files. Remote code execution is possible if the server uses Apache with libapache2-mod-php and the attacker accesses the file before it is removed by unlink() at the end of the request.
