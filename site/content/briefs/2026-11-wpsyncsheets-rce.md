---
brief_id: brief-2026-11-06-wpsyncsheets-rce
event_id: brief-2026-11-06-wpsyncsheets-rce
revision: 1
activity_at: "2026-11-06T13:11:50Z"
title: 'WPSyncSheets For Contact Form 7: PHP Object Injection and Remote Code Execution (CVE-2026-104010)'
slug: 2026-11-wpsyncsheets-rce
description: The WPSyncSheets For Contact Form 7 WordPress plugin is vulnerable to unauthenticated remote code execution via insufficient sanitization of form submission fields and insecure deserialization.
date: "2026-11-06T13:11:50Z"
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
  - WPSyncSheets For Contact Form 7 – CF7 Google Sheets Connector & Save to Database (<= 1.8.0)
cves:
  - id: CVE-2026-104010
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104010
---

The WPSyncSheets For Contact Form 7 - CF7 Google Sheets Connector & Save to Database plugin for WordPress (versions up to and including 1.8.0) is vulnerable to Remote Code Execution via non-system CF7 field parameters. The vulnerability stems from insufficient sanitization of submission values before database storage and the lack of an allowed_classes restriction on maybe_unserialize() during admin retrieval. While PHP Object Injection occurs regardless, successful remote code execution requires a configured Google Sheets access token, which triggers the autoloading of the Monolog 2.10.0 library used as an exploit gadget chain.
