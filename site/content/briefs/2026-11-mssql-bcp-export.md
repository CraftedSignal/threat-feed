---
brief_id: brief-2026-11-25-mssql-bcp-export
event_id: brief-2026-11-25-mssql-bcp-export
revision: 1
activity_at: "2026-11-25T16:27:03Z"
title: Unauthorized Data Export via BCP Utility
slug: 2026-11-mssql-bcp-export
description: Threat actors have been observed using the Microsoft BCP utility to exfiltrate data from MSSQL databases, a technique that detection engineers should monitor via command-line arguments.
date: "2026-11-25T16:27:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic follows SigmaHQ standard.
tags:
  - execution
  - exfiltration
  - mssql
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: Attackers were seen saving their malware to a database column or table and then later extracting it via bcp.exe into a file.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_bcp_export_data.yml
rules:
  - title: Detect BCP Data Export
    description: Detects the use of bcp.exe to export data from a table or via a query, a technique used by attackers to extract data stored in databases.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - exfiltration
    techniques:
      - T1048
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor for bcp.exe command-line usage patterns indicative of data export.
      owner: Detection Engineering
      due: 72h
      evidence: Source documentation of attacker abuse of bcp.exe.
  hunt_leads:
    - lead: Review process logs for bcp.exe execution occurring outside of scheduled maintenance windows.
      technique_id: T1048
      data_needed:
        - Process creation events (Event ID 1)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Observed attacker usage of bcp.exe for data extraction.
---

## Overview

The BCP (Bulk Copy Program) utility is a legitimate tool used for importing and exporting data between Microsoft SQL Server and data files. Threat actors have been documented leveraging this utility to extract sensitive information or malware payloads stored within database tables. By executing BCP with specific flags, adversaries can export entire tables or results from custom SQL queries to local or remote files.

## Attack Chain

1. Initial access to the database server (e.g., via compromised credentials or SQL injection).
2. Malware or malicious scripts are written into database columns or tables.
3. The adversary executes `bcp.exe` via command-line interface.
4. BCP processes the table or query and writes the output to a specified file path.

## Recommendation

Implement process-creation monitoring to detect the invocation of `bcp.exe` with suspicious command-line parameters. Filter for known legitimate administrative tasks to reduce noise. Maintain strict access control to MSSQL server environments and enforce principle of least privilege for database service accounts.
