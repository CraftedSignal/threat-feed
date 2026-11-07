---
brief_id: brief-2026-11-07-ibm-api-connect-attr-modification
event_id: brief-2026-11-07-ibm-api-connect-attr-modification
revision: 1
activity_at: "2026-11-07T05:55:55Z"
title: 'IBM API Connect: Information disclosure via attribute modification (CVE-2026-17394)'
slug: 2026-11-ibm-api-connect-attr-modification
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a vulnerability that could allow a remote authenticated attacker to obtain sensitive information due to improperly controlled modification of object attributes.
date: "2026-11-07T05:55:55Z"
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
products:
  - IBM API Connect 10.0.8.0 through 10.0.8.12
  - IBM API Connect 12.1.0.0 through 12.1.1.2
cves:
  - id: CVE-2026-17394
    cvss: 9.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17394
---

IBM API Connect (versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2) is affected by a vulnerability involving improperly controlled modification of object attributes. A remote authenticated attacker may provide a user-supplied value that changes an access-related setting, potentially leading to the exposure of sensitive information. The CVSS v3.1 base score for this vulnerability is 9.6.
