---
title: CISA Adds Google Skia and Chromium V8 Vulnerabilities to KEV Catalog
slug: 2026-03-cisa-kev-google-vulnerabilities
description: CISA added CVE-2026-3909, an out-of-bounds write vulnerability in Google Skia, and CVE-2026-3910, an unspecified vulnerability in Google Chromium V8 to its Known Exploited Vulnerabilities Catalog, based on evidence of active exploitation, highlighting the need for timely remediation.
date: "2026-03-14T10:00:00Z"
severities:
  - high
type: threat
types:
  - threat
tags:
  - vulnerability
  - chrome
  - skia
  - cve-2026-3909
  - cve-2026-3910
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.cisa.gov/news-events/alerts/2026/03/13/cisa-adds-two-known-exploited-vulnerabilities-catalog
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - https://www.cve.org/CVERecord?id=CVE-2026-3909
  - https://www.cve.org/CVERecord?id=CVE-2026-3910
rules:
  - title: Detect Chrome Executing From Unusual Location
    description: Detects Google Chrome execution from unusual paths, which can indicate exploitation or malware injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Skia Library Loaded by Suspicious Processes
    description: Detects the Skia library being loaded by processes that are not typically associated with it.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218.011
    data_sources:
      - image_load
      - windows
rules_count: 2
---

On March 13, 2026, CISA added CVE-2026-3909, an out-of-bounds write vulnerability in Google Skia, and CVE-2026-3910, an unspecified vulnerability in Google Chromium V8, to its Known Exploited Vulnerabilities (KEV) Catalog. These vulnerabilities are actively being exploited in the wild and are considered frequent attack vectors. While CISA's BOD 22-01 mandates Federal Civilian Executive Branch (FCEB) agencies to remediate these vulnerabilities, CISA strongly urges all organizations to prioritize…
