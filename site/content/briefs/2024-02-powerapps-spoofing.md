---
title: CVE-2026-26149 Microsoft Power Apps Spoofing Vulnerability
slug: 2024-02-powerapps-spoofing
description: A spoofing vulnerability exists in Microsoft Power Apps, identified as CVE-2026-26149, potentially allowing an attacker to mislead users or gain unauthorized access.
date: "2026-04-20T14:00:00Z"
severities:
  - medium
tags:
  - CVE-2026-26149
  - powerapps
  - spoofing
cves:
  - id: CVE-2026-26149
    cvss: 9
    epss: 0.00058
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26149
rules:
  - title: Detect Suspicious Power Apps Activity
    description: Detects unusual activity within Microsoft Power Apps that may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - windows
  - title: Detect Potential Power Apps Phishing via Referer
    description: Detects potential phishing attempts targeting Power Apps users by analyzing the HTTP Referer header.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-26149 describes a spoofing vulnerability affecting Microsoft Power Apps. While the specifics of exploitation are not detailed in the initial advisory, successful exploitation could allow an attacker to craft deceptive Power Apps or manipulate existing ones to display misleading information, potentially leading to credential theft or other forms of social engineering. The vulnerability's impact is contingent on user interaction, as a user must be tricked into interacting with the…
