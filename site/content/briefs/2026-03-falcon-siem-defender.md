---
title: CrowdStrike Falcon SIEM Integration with Microsoft Defender
slug: 2026-03-falcon-siem-defender
description: CrowdStrike's Falcon Next-Gen SIEM expands to support third-party EDR solutions like Microsoft Defender, streamlining SOC modernization by unifying detection, investigation, and response across diverse environments without replacing existing endpoint agents.
date: "2026-03-29T12:00:00Z"
severities:
  - medium
tags:
  - siem
  - edr
  - microsoft-defender
  - falcon-siem
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detect Potential Initial Access via Suspicious Process Execution (Generic)
    description: Detects potential initial access attempts by monitoring for suspicious processes not typically seen in the environment based on the Falcon SIEM integration data.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detecting Microsoft Defender Telemetry Data in Falcon SIEM
    description: This rule detects the ingestion of Microsoft Defender telemetry within the CrowdStrike Falcon SIEM, verifying integration.
    platform: sigma
    severity: informational
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike is enhancing its Falcon Next-Gen SIEM to incorporate telemetry from third-party EDR solutions, beginning with Microsoft Defender. This integration aims to provide organizations with a consolidated security operations center (SOC) view, reducing the need to replace existing endpoint agents. The initiative addresses the increasing complexity of modern attacks that span multiple domains, including endpoint, identity, network, and cloud. Legacy SIEMs often struggle with data ingestion…
