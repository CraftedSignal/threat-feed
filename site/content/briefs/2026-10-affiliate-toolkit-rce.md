---
brief_id: brief-2026-10-29-affiliate-toolkit-rce
event_id: brief-2026-10-29-affiliate-toolkit-rce
revision: 1
activity_at: "2026-10-29T20:14:45Z"
title: 'affiliate-toolkit WordPress plugin: Arbitrary file upload (CVE-2026-111255)'
slug: 2026-10-affiliate-toolkit-rce
description: The affiliate-toolkit WordPress plugin contains an arbitrary file upload vulnerability in the upload_image function, allowing authenticated attackers with contributor-level access or higher to achieve remote code execution.
date: "2026-10-29T20:14:45Z"
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
  - affiliate-toolkit – Multi-Network Affiliate & Amazon Product Display plugin for WordPress (<= 3.9.2)
cves:
  - id: CVE-2026-111255
    cvss: 7.5
    epss: 0.00515
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111255
---

The affiliate-toolkit - Multi-Network Affiliate & Amazon Product Display plugin for WordPress (versions up to and including 3.9.2) is vulnerable to arbitrary file upload via the `upload_image` function. The vulnerability is caused by insufficient file type validation, specifically a weak Content-Type prefix check and extension derivation from an attacker-controlled URL path without stripping dangerous extensions. Exploitation allows authenticated users with contributor-level access or higher to upload executable files, potentially leading to remote code execution. Successful exploitation requires the "import product image" option to be enabled.
