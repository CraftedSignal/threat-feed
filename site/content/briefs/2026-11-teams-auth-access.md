---
brief_id: brief-2026-11-25-teams-auth-access
event_id: brief-2026-11-25-teams-auth-access
revision: 1
activity_at: "2026-11-25T16:22:04Z"
title: Unauthorized access to Microsoft Teams authentication tokens
slug: 2026-11-teams-auth-access
description: Threat actors may target local Microsoft Teams data repositories to extract authentication tokens and session information for unauthorized account access.
date: "2026-11-25T16:22:04Z"
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
tags:
  - credential-access
  - microsoft-teams
products:
  - Microsoft Teams
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: Detects an access to authentication tokens and accounts of Microsoft Teams desktop application.
    confidence_band: high
references:
  - https://www.bleepingcomputer.com/news/security/microsoft-teams-stores-auth-tokens-as-cleartext-in-windows-linux-macs/
  - https://web.archive.org/web/20230726144455/https://www.vectra.ai/blogpost/undermining-microsoft-teams-security-by-mining-tokens
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_teams_suspicious_objectaccess.yml
rules:
  - title: Suspicious Teams Application Related ObjectAcess Event
    description: Detects an access to authentication tokens and accounts of Microsoft Teams desktop application.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1528
    data_sources:
      - windows
      - security
rules_count: 1
---

## Overview
Microsoft Teams stores authentication tokens and session data on the local file system. Unauthorized access to these files, located within the application's local storage and cookie directories, allows for potential session hijacking and impersonation of users. This activity can be identified via Windows Security event auditing when processes access these specific sensitive paths.

## Attack Chain
Attackers target the local file system where Microsoft Teams stores authentication tokens. Accessing these files allows an attacker to retrieve session data, which may lead to the compromise of the victim's account.

## Impact
Successful extraction of authentication tokens allows unauthorized parties to bypass primary authentication mechanisms, leading to session hijacking and unauthorized access to resources accessible through the victim's Teams account.

## Recommendation
Monitor for unauthorized process access to Teams local storage using Windows Security auditing. Organizations should ensure that only the legitimate Microsoft Teams process is accessing these sensitive directories.
