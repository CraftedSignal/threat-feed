---
brief_id: brief-2026-11-18-microsoft-dialer-c2
event_id: brief-2026-11-18-microsoft-dialer-c2
revision: 1
activity_at: "2026-11-18T13:50:29Z"
title: Outbound Network Connection Initiated By Microsoft Dialer
slug: 2026-11-microsoft-dialer-c2
description: The legacy Windows Phone Dialer utility is used by information-stealing malware for process injection to facilitate unauthorized outbound Command and Control (C2) communications.
date: "2026-11-18T13:50:29Z"
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
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.001
    subtechnique_name: Web Protocols
    evidence: is used to make C2 connections
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_dialer_initiated_connection.yml
  - https://tria.ge/240301-rk34sagf5x/behavioral2
  - https://app.any.run/tasks/6720b85b-9c53-4a12-b1dc-73052a78477d
  - https://research.checkpoint.com/2023/rhadamanthys-v0-5-0-a-deep-dive-into-the-stealers-components/
  - https://strontic.github.io/xcyclopedia/library/dialer.exe-0B69655F912619756C704A0BF716B61F.html
rules:
  - title: Outbound Network Connection Initiated By Microsoft Dialer
    description: Detects outbound network connection initiated by Microsoft Dialer (dialer.exe), a technique associated with information stealers.
    platform: sigma
    severity: high
    tactics:
      - command-and-control
      - execution
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

## Overview
Microsoft Dialer (dialer.exe) is a built-in utility application included in various versions of the Microsoft Windows operating system, designed for managing phone calls. This legacy process has been identified as a target for information stealers, such as the Rhadamanthys malware, which may utilize the process for process injection.

## Attack Chain
Malware may utilize the dialer.exe process as a host for malicious code via process injection. Once injected, the process is used to establish outbound network connections to facilitate Command and Control (C2) communications.

## Impact
Unauthorized network communications may originate from the legitimate Windows dialer.exe binary.

## Recommendation
Monitor for outbound network connections initiated by dialer.exe. Investigate such connections as they are generally indicative of malicious activity given the nature of the application.
