---
brief_id: brief-2026-11-17-shadowcloud
event_id: brief-2026-11-17-shadowcloud
revision: 1
activity_at: "2026-11-17T08:59:19Z"
title: 'Operation ShadowCloud: GraphDoor Backdoor Analysis'
slug: 2026-11-shadowcloud
description: The GraphDoor backdoor, part of Operation ShadowCloud, utilizes the Microsoft Graph API for command-and-control and modular plugin delivery via SharePoint.
date: "2026-11-17T08:59:19Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
tags:
  - backdoor
  - cloud-c2
  - microsoft-graph
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The malware first opens a TLS connection to login.microsoftonline.com... authenticates the malicious application... and returns an access token that the backdoor later uses to communicate with the Microsoft Graph API.
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: It issues a Microsoft Graph PUT request that creates a file... in a SharePoint document library.
references:
  - https://securelist.com/operation-shadowcloud-graphdoor/122005/
iocs:
  - type: hash_md5
    value: 14ec33ea808e697870d00c5e434c2952
ioc_counts:
  hash_md5: 1
rules:
  - title: GraphDoor Named Pipe Creation
    description: Detects the creation of named pipes following the GraphDoor pattern \\.\pipe\p%lu.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

## Overview
Operation ShadowCloud involves the use of the GraphDoor backdoor (MD5 14ec33ea808e697870d00c5e434c2952). The backdoor utilizes the Microsoft Graph API for C2 communication, authenticating a malicious application registration via login.microsoftonline.com to interact with SharePoint document libraries and lists.

## Attack Chain
- Persistence and Initialization: GraphDoor creates a named pipe (\\.\pipe\p%lu) and a hidden directory at C:\ProgramData\Intel_Log\&lt;random-GUID>.
- Authentication: The malware authenticates a malicious application registration against login.microsoftonline.com using embedded OAuth credentials to obtain an access token.
- C2 and Exfiltration: It connects to graph.microsoft.com to store encrypted data in files masquerading as .js.map files within SharePoint.
- Plugin Delivery: It retrieves modular plugins (scr.ts, pr.ts, kl.ts) from SharePoint lists and executes them in memory using a COFF object loader.

## Impact
Compromised hosts may be subjected to keylogging, process listing, screen capture, and arbitrary command execution via 'shell' or 'adsmload' commands.

## Recommendation
Review and audit OAuth application registrations and service principals that possess Graph API permissions. Monitor egress traffic for connections to login.microsoftonline.com and graph.microsoft.com.
