---
brief_id: brief-2026-10-29-bulk-share-location-sender
event_id: brief-2026-10-29-bulk-share-location-sender
revision: 1
activity_at: "2026-10-29T23:08:23Z"
title: 'Bulk Share: Location Sender insecure component permissions (CVE-2026-107032)'
slug: 2026-10-bulk-share-location-sender
description: 'Insecure permissions in Bulk Share: Location Sender v2.1.0 (versionCode 5) allow unauthorized attackers to invoke an exported component, leading to arbitrary data access and control of data flow.'
date: "2026-10-29T23:08:23Z"
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
  - cpe:2.3:a:bulk_share:location_sender:*:*:*:*:*:*:*:*
vendors:
  - Bulk Share
products:
  - Location Sender (v2.1.0)
cves:
  - id: CVE-2026-107032
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107032
---

CVE-2026-107032 identifies an insecure permission configuration in Bulk Share: Location Sender v2.1.0 (versionCode 5). The application exports a component that allows unauthorized attackers to invoke it, resulting in arbitrary data access and control of data flow.

## Impact
The vulnerability has a CVSS v3.1 Base Score of 9.1.
