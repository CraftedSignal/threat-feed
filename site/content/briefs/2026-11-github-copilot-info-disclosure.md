---
brief_id: brief-2026-11-10-github-copilot-info-disclosure
event_id: brief-2026-11-10-github-copilot-info-disclosure
revision: 1
activity_at: "2026-11-10T22:47:07Z"
title: 'GitHub Copilot for JetBrains: Information disclosure vulnerability (CVE-2026-83953)'
slug: 2026-11-github-copilot-info-disclosure
description: A command injection vulnerability in the GitHub Copilot extension for JetBrains IDEs (CVE-2026-83953) allows an authorized attacker to disclose information locally.
date: "2026-11-10T22:47:07Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:github:copilot_for_jetbrains:*:*:*:*:*:*:*:*
tags:
  - cve-2026-83953
  - information-disclosure
  - vulnerability
vendors:
  - GitHub
products:
  - GitHub Copilot for JetBrains
cves:
  - id: CVE-2026-83953
    cvss: 5.5
    kev_status: "false"
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-83953
---

CVE-2026-83953 is an information disclosure vulnerability caused by improper neutralization of special elements used in a command within the GitHub Copilot extension for JetBrains. This vulnerability allows an authorized attacker to disclose information locally.
