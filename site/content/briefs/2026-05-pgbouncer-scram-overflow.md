---
title: CVE-2026-6665 PgBouncer SCRAM Buffer Overflow Vulnerability
slug: 2026-05-pgbouncer-scram-overflow
description: CVE-2026-6665 is a buffer overflow vulnerability in the PgBouncer's SCRAM implementation that could lead to remote code execution.
date: "2026-05-10T07:08:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - buffer overflow
  - pgbouncer
  - scram
  - rce
vendors:
  - Microsoft
products:
  - Security Update Guide
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6665
    cvss: 8.1
    epss: 0.00017
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-6665
rules:
  - title: Detect CVE-2026-6665 Exploitation Attempt - Suspicious SCRAM Authentication Message Size
    description: Detects CVE-2026-6665 exploitation attempt — monitors network traffic for SCRAM authentication messages exceeding a reasonable size threshold, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2026-6665 Exploitation Attempt - Process Crash with SCRAM in Call Stack
    description: Detects CVE-2026-6665 exploitation attempt — identifies process crashes within PgBouncer where the SCRAM authentication routines are present in the call stack, indicating a potential buffer overflow.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-6665 describes a buffer overflow vulnerability within the SCRAM (Salted Challenge Response Authentication Mechanism) implementation of PgBouncer, a lightweight connection pooler for PostgreSQL. An attacker could exploit this vulnerability by sending a specially crafted authentication request to PgBouncer, potentially leading to arbitrary code execution on the affected system. The Microsoft Security Response Center (MSRC) published information about this vulnerability. Successful exploitation could allow an attacker to gain unauthorized access to the database server and compromise sensitive data. Due to the nature of buffer overflows, exploitation can result in service disruption or complete system takeover.

## Attack Chain

1. An attacker identifies a vulnerable PgBouncer instance.
2. The attacker initiates a connection to the PgBouncer instance.
3. The attacker begins the SCRAM authentication process.
4. The attacker sends a malicious SCRAM authentication message containing an oversized payload.
5. The oversized payload overflows the allocated buffer in PgBouncer's memory.
6. The buffer overflow overwrites adjacent memory regions, potentially including executable code.
7. The attacker gains control of the execution flow by overwriting critical data or function pointers.
8. The attacker executes arbitrary code on the server, potentially gaining access to sensitive data or escalating privileges.

## Impact

Successful exploitation of CVE-2026-6665 allows a remote attacker to execute arbitrary code on the system running the vulnerable PgBouncer instance. This could lead to complete system compromise, data exfiltration, or denial of service. The impact of successful exploitation is high, as it can lead to unauthorized access to sensitive data, disruption of services, and potential financial losses.

## Recommendation

*   Deploy the Sigma rules provided below to your SIEM to detect exploitation attempts.
*   Monitor network traffic for unusually large SCRAM authentication messages targeting PgBouncer instances (see network_connection rule).
*   Investigate and patch vulnerable PgBouncer instances immediately to prevent potential exploitation.
