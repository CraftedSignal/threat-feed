---
brief_id: brief-2026-11-08-grav-lightbox-gallery
event_id: brief-2026-11-08-grav-lightbox-gallery
revision: 1
activity_at: "2026-11-08T15:30:24Z"
title: 'Grav Lightbox Gallery: Arbitrary file read via insecure method calls (CVE-2026-124434)'
slug: 2026-11-grav-lightbox-gallery
description: The Grav Lightbox Gallery plugin 1.1.0 before 1.3.2 on Grav 2.x allows page editors to read server-readable files by invoking unauthorized media methods.
date: "2026-11-08T15:30:24Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:grav:lightbox_gallery_plugin:*:*:*:*:*:*:*:*
vendors:
  - Grav
products:
  - Lightbox Gallery plugin (< 1.3.2)
cves:
  - id: CVE-2026-124434
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124434
---

The Grav Lightbox Gallery plugin (1.1.0 before 1.3.2) on Grav 2.x calls medium methods named in image, thumb, or thumb_options shortcode values without checking the core's allowed media actions. A page editor can chain addMetaFile with value, toYaml, or toJson to read server-readable YAML files - such as account password hashes, 2FA secrets, and API keys - into a publicly viewable page.
