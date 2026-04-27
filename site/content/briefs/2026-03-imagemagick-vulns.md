---
title: ImageMagick Multiple Vulnerabilities Leading to DoS, Code Execution, or Data Manipulation
slug: 2026-03-imagemagick-vulns
description: Multiple vulnerabilities in ImageMagick could allow an attacker to perform a denial of service attack, execute arbitrary code, or manipulate data.
date: "2026-03-31T08:55:55Z"
severities:
  - critical
tags:
  - imagemagick
  - vulnerability
  - dos
  - code_execution
  - data_manipulation
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0148
rules:
  - title: Detect Suspicious Image Uploads to Web Servers
    description: Detects potentially malicious image uploads based on file extensions and content types, possibly targeting ImageMagick vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect ImageMagick Spawning Suspicious Processes
    description: Detects ImageMagick processes spawning child processes with potentially malicious command-line arguments, indicative of code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

ImageMagick is a software suite to create, edit, compose, or convert bitmap images. According to the BSI advisory, multiple unspecified vulnerabilities exist within ImageMagick that, if exploited, could lead to significant security repercussions. An attacker could leverage these vulnerabilities to trigger a denial-of-service (DoS) condition, potentially disrupting services that rely on ImageMagick for image processing. Furthermore, successful exploitation could grant the attacker the ability to…
