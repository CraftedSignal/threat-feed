---
brief_id: brief-2026-11-03-yeti-path-traversal
event_id: brief-2026-11-03-yeti-path-traversal
revision: 1
activity_at: "2026-11-03T22:20:32Z"
title: 'Yeti: Path traversal remote file write (CVE-2026-63500)'
slug: 2026-11-yeti-path-traversal
description: An authenticated low-privileged user can exploit a path traversal vulnerability in the Yeti Forensics Intelligence platform to write content with a .yaml suffix outside the intended archive directory.
date: "2026-11-03T22:20:32Z"
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
products:
  - Yeti (< 2.5.1)
cves:
  - id: CVE-2026-63500
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63500
---

Yeti versions prior to 2.5.1 allow an authenticated low-privileged user to import a DFIQ object via `POST /api/v2/dfiq/from_yaml` with a UUID containing traversal sequences. This value is later interpolated into a filesystem path in `POST /api/v2/dfiq/to_archive`, resulting in arbitrary file writes limited by the permissions of the Yeti service account.
