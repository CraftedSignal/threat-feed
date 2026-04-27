---
title: PraisonAI SSRF Vulnerability (CVE-2026-34954)
slug: 2026-04-praisonai-ssrf
description: PraisonAI before version 1.5.95 is vulnerable to server-side request forgery (SSRF) due to improper URL validation in the FileTools.download_file() function, potentially allowing attackers to access internal resources.
date: "2026-04-04T14:30:00Z"
severities:
  - high
tags:
  - SSRF
  - CVE-2026-34954
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34954
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34954
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-44c2-3rw4-5gvh
rules:
  - title: PraisonAI Suspicious Outbound Connection
    description: Detects suspicious outbound connections originating from PraisonAI server, indicating potential SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: PraisonAI SSRF - HTTP Request to Internal IP
    description: Detects HTTP requests from PraisonAI to internal IP ranges, indicative of SSRF attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to a server-side request forgery (SSRF) vulnerability (CVE-2026-34954) in versions prior to 1.5.95. The vulnerability resides within the `FileTools.download_file()` function of the `praisonaiagents` component. The function validates the destination path of downloaded files but fails to properly sanitize or validate the URL parameter. This allows a malicious actor to supply a crafted URL. The httpx.stream() function, configured with…
