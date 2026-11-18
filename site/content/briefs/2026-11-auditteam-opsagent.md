---
brief_id: brief-2026-11-18-auditteam-opsagent
event_id: brief-2026-11-18-auditteam-opsagent
revision: 1
activity_at: "2026-11-18T09:23:14Z"
title: 'AuditTeam: OpsAgent framework and forced audit extortion'
slug: 2026-11-auditteam-opsagent
description: AuditTeam is an active threat group using the modular OpsAgent framework for reconnaissance, data theft, and encryption, while employing an extortion model that demands an 'Audit & Consulting fee' to provide vulnerability reports.
date: "2026-11-18T09:23:14Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - AuditTeam
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://securelist.com/auditteam-opsagent-forced-audit/122031/
  observed_at: "2026-03-10T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
tags:
  - ransomware
  - extortion
  - opsagent
affected_os:
  - windows
references:
  - https://securelist.com/auditteam-opsagent-forced-audit/122031/
---

## Overview
AuditTeam is an active threat group that has targeted organizations across at least 14 countries since January 2026. The group utilizes the OpsAgent framework, a modular implant capable of file system management, process injection, privilege escalation, keylogging, and network pivoting. AuditTeam employs an extortion model demanding an 'Audit & Consulting fee' in exchange for vulnerability reports to prevent the public disclosure of stolen data.

## Attack Chain
1. The campaign utilizes multiple loader variants (C, .NET, and Rust) to unpack the OpsAgent payload. The Rust version performs in-process execution, while others use process injection.
2. The OpsAgent implant operates using a worker-thread architecture and can retrieve C2 addresses from a public GitHub repository. 
3. The AV/EDR killer module installs a digitally signed driver disguised as Beijing Jiangmin Antivirus (KV series), utilizing the \KvCorePortX0 filter port, to terminate security products.
4. The cryptor module terminates database and backup processes before encrypting files using AES-CBC or ChaCha20 with X25519 key exchange.
5. Upon completion, a ransom note is dropped demanding an 'Audit & Consulting fee'.

## Impact
Victims suffer from full-scale host compromise, theft of sensitive data, and the encryption of critical business assets. The ransom note claims that payment results in the delivery of a vulnerability report rather than the release of the stolen data archive to the public internet.

## Recommendation
Monitor for the installation of unexpected kernel drivers, specifically those using the \KvCorePortX0 filter port, and audit internal use of GitHub to obtain C2 configuration data.
