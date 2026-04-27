---
title: CrowdStrike Falcon Next-Gen SIEM Supports Third-Party EDR Tools
slug: 2026-03-falcon-siem-third-party-edr
description: CrowdStrike Falcon Next-Gen SIEM is expanding to support third-party EDR solutions, starting with Microsoft Defender, enabling organizations to extend their AI-native SOC across their ecosystem by unifying detection, investigation, and response.
date: "2026-03-28T09:13:21Z"
severities:
  - medium
tags:
  - SIEM
  - EDR
  - Microsoft Defender
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detecting ExtraHop Data Source
    description: Detects the presence of ExtraHop as a data source within a SIEM environment, which can be indicative of advanced network monitoring and potential threat hunting activities.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1592
    data_sources:
      - webserver
      - linux
  - title: Detecting Amazon S3 Athena Data Source
    description: Detects the presence of Amazon S3 Athena as a data source within a SIEM environment, which can be indicative of cloud log analysis.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1592
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On March 23, 2026, CrowdStrike announced that its Falcon Next-Gen SIEM will support third-party EDR solutions, starting with Microsoft Defender. This enhancement allows organizations to modernize their SOC without replacing existing endpoint agents. The integration aims to address the challenges posed by adversaries exploiting cross-domain gaps across endpoint, identity, network, and cloud environments. Legacy SIEMs often impose a "data tax" for full ingestion, while siloed tools create blind…
