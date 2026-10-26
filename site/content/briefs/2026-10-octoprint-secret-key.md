---
brief_id: brief-2026-10-26-octoprint-secret-key
event_id: brief-2026-10-26-octoprint-secret-key
revision: 1
activity_at: "2026-10-26T21:46:44Z"
title: 'OctoPrint: Hard-coded cryptographic key in Flask Secret Key Handler (CVE-2014-125135)'
slug: 2026-10-octoprint-secret-key
description: A security vulnerability has been detected in OctoPrint 1.0.0/1.1.0 involving a hard-coded cryptographic key in the Flask Secret Key Handler.
date: "2026-10-26T21:46:44Z"
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
  - OctoPrint 1.0.0
  - OctoPrint 1.1.0
cves:
  - id: CVE-2014-125135
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2014-125135
---

A vulnerability exists in the Flask Secret Key Handler component of OctoPrint versions 1.0.0 and 1.1.0. The implementation uses a hard-coded cryptographic key. The attack may be performed from remote. 

## Recommendation
Upgrading to version 1.11.1 is able to address this issue.
