---
brief_id: brief-2026-11-04-sql-tools-powershell
event_id: brief-2026-11-04-sql-tools-powershell
revision: 1
activity_at: "2026-11-04T03:53:51Z"
title: 'Microsoft SQL Server: Potential execution via sqltoolsps.exe'
slug: 2026-11-sql-tools-powershell
description: The sqltoolsps.exe utility, a component of Microsoft SQL Server Management Studio, can be used to execute PowerShell code. Script blocks are not logged in this case, allowing this utility to bypass protection mechanisms based on log analysis.
date: "2026-11-04T03:53:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.execution
  - attack.stealth
  - attack.t1059.001
  - attack.t1127
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/8283d8d91552213ded165fd36deb6cb9534cb443/yml/OtherMSBinaries/Sqltoolsps.yml
  - https://twitter.com/pabraeken/status/993298228840992768
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_mssql_sqltoolsps_susp_execution.yml
rules:
  - title: Detect SQL Client Tools PowerShell Session Execution
    platform: sigma
    severity: medium
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

The utility sqltoolsps.exe is included with Microsoft SQL Server Management Studio. This binary can be used to execute PowerShell code. Because script blocks are not logged during execution via this utility, it serves as a mechanism to bypass log-based protection mechanisms.
