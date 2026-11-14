---
brief_id: brief-2026-11-14-json-xs-vulnerabilities
event_id: brief-2026-11-14-json-xs-vulnerabilities
revision: 1
activity_at: "2026-11-14T18:50:32Z"
title: 'JSON::XS: Memory and stack exhaustion vulnerabilities (CVE-2026-124536, CVE-2026-124539, CVE-2026-124540)'
slug: 2026-11-json-xs-vulnerabilities
description: Multiple vulnerabilities in JSON::XS versions before 4.05 allow for memory and stack exhaustion when processing specifically crafted JSON input.
date: "2026-11-14T18:50:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
products:
  - JSON::XS
product_versions:
  - product: JSON::XS
    range: < 4.05
affected_os:
  - Perl
cves:
  - id: CVE-2026-124536
    kev_status: "false"
  - id: CVE-2026-124539
    kev_status: "false"
  - id: CVE-2026-124540
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-124536
  - https://cveawg.mitre.org/api/cve/CVE-2026-124539
  - https://cveawg.mitre.org/api/cve/CVE-2026-124540
  - https://seclists.org/oss-sec/2026/q4/706
---

## Overview

Three vulnerabilities have been identified in the Perl module JSON::XS affecting versions prior to 4.05, leading to potential process memory exhaustion or stack exhaustion.

### Vulnerabilities

- CVE-2026-124536: The incr_parse function fails to correctly limit memory usage. A NUL byte within the first max_size bytes allows a peer to stream data that bypasses max_size checks, causing the buffer to grow until process memory is exhausted.
- CVE-2026-124539: When decode_hv rejects an object due to a missing colon, the decoded key is not freed. Repeated requests for rejected documents lead to memory exhaustion.
- CVE-2026-124540: When allow_tags is enabled, the decode_tag function processes nested tagged values without counting them against max_depth. A sequence of "(" bytes can trigger stack exhaustion and a segmentation fault.

## Recommendation

Upgrade the JSON::XS module to version 4.05 or later to resolve these vulnerabilities.
