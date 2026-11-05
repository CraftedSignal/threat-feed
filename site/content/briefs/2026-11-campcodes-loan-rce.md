---
brief_id: brief-2026-11-05-campcodes-loan-rce
event_id: brief-2026-11-05-campcodes-loan-rce
revision: 1
activity_at: "2026-11-05T00:07:46Z"
title: 'Campcodes Complete Advance Loan Management System: Unrestricted file upload (CVE-2026-122047)'
slug: 2026-11-campcodes-loan-rce
description: Campcodes Complete Advance Loan Management System 1.0 contains an unrestricted file upload vulnerability in /loan/application/banner.php via the image argument.
date: "2026-11-05T00:07:46Z"
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
  - cpe:2.3:a:campcodes:complete_advance_loan_management_system:*:*:*:*:*:*:*:*
vendors:
  - Campcodes
products:
  - Complete Advance Loan Management System (1.0)
cves:
  - id: CVE-2026-122047
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122047
---

A security vulnerability has been detected in Campcodes Complete Advance Loan Management System 1.0. The vulnerability exists within the 'move_uploaded_file' function of the file '/loan/application/banner.php'. Manipulation of the 'image' argument leads to an unrestricted file upload. The attack may be launched remotely, and the exploit has been disclosed publicly.
